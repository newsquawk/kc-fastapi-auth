"""Authentication service using JWT and JWKS for token validation."""

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Union

import httpx
import jwt
from jwt import PyJWK, PyJWKSet
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)

# Default lifespan (seconds) of the cached JWKS before a refresh is triggered.
# Mirrors PyJWKClient's historical default of 5 minutes.
DEFAULT_JWKS_CACHE_LIFESPAN = 300

# Default timeout for the async JWKS HTTP fetch. Deliberately tight: the fetch
# runs inside the single-flight lock, so a hung endpoint would otherwise stall
# every concurrent cache-miss validation until it fires. A fast connect timeout
# fails quickly on a dead endpoint; the read timeout bounds a slow response.
# Callers can override with a plain float (applied to all phases) or their own
# httpx.Timeout for finer control.
DEFAULT_JWKS_TIMEOUT = httpx.Timeout(5.0, connect=2.0)


class JWKSUnavailableError(Exception):
    """
    Raised when the JWKS endpoint cannot be reached or returns unusable data.

    This signals an upstream/server-side failure (the identity provider is down,
    timing out, or returning garbage) as opposed to a client presenting a bad
    token. It is mapped to an HTTP 503 by :meth:`AuthService.verify_and_decode_token`
    so callers can tell "we couldn't validate right now" apart from "your token
    is invalid" (401).
    """

# Shared symmetric secret used by the stub (fake-Keycloak) flow. Both the
# issuer (:class:`newsquawk_auth.stub.StubIdentityProvider`) and the validator
# (:class:`AuthService` in stub mode) default to this so zero-config local dev
# works out of the box. Override it in both places for anything beyond a laptop.
# It is deliberately obvious that this is not a production secret.
DEFAULT_STUB_SECRET = "insecure-stub-secret-do-not-use-in-production"

# Algorithm used for stub tokens. Kept strictly separate from the production
# RS256/JWKS path so a stub HS256 token can never be accepted by a real
# validator (and vice versa), avoiding algorithm-confusion attacks.
STUB_ALGORITHM = "HS256"


class AuthService:
    """
    Service class for handling JWT authentication with remote JWKS certificates.

    This service validates JWT tokens by fetching signing keys from a remote
    JWKS endpoint (e.g., Keycloak). The fetch is performed asynchronously with
    httpx and the resulting keys are cached per instance, so token validation
    never blocks the event loop. Concurrent cache misses are coalesced into a
    single fetch via an ``asyncio.Lock`` (single-flight).
    """

    def __init__(
        self,
        jwks_url: Optional[str] = None,
        audience: Optional[str] = None,
        algorithms: Optional[list[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        stub_mode: bool = False,
        stub_secret: Optional[str] = None,
        dev_mode: bool = False,
        jwks_cache_lifespan: int = DEFAULT_JWKS_CACHE_LIFESPAN,
        jwks_timeout: Union[float, httpx.Timeout] = DEFAULT_JWKS_TIMEOUT,
    ):
        """
        Initialize the authentication service.

        Args:
            jwks_url: URL to the JWKS endpoint (e.g., Keycloak certs endpoint).
                Required unless stub_mode is True.
            audience: Expected audience (aud) claim in the JWT token. Optional.
                When set, the token's aud claim must be present and match. When
                None, audience validation is disabled entirely — signature and
                expiry are still verified. Applies in both real and stub mode.
            algorithms: List of allowed signing algorithms (default: ["RS256"]).
                Ignored in stub mode, which always uses HS256.
            custom_headers: Optional custom headers for JWKS client requests
            stub_mode: If True, run against the stub (fake-Keycloak) flow:
                tokens are verified as real HS256 JWTs signed with a shared
                symmetric secret (see :data:`DEFAULT_STUB_SECRET`) rather than
                against a remote JWKS endpoint. Signature and expiry ARE
                verified — only the trust root differs. Tokens are minted by
                :class:`newsquawk_auth.stub.StubIdentityProvider`. NEVER enable
                this in production.
            stub_secret: Shared HS256 secret used to verify stub tokens. Must
                match the secret the issuer signs with. Defaults to
                :data:`DEFAULT_STUB_SECRET`. Only used when stub_mode is True.
            dev_mode: Deprecated alias for ``stub_mode``, kept for backward
                compatibility. Note the mechanism has changed: stub tokens are
                now signature-verified HS256 JWTs, not looked up in a dict.
            jwks_cache_lifespan: Seconds to cache the fetched JWKS before a
                refresh is triggered on the next validation (default 300).
                Ignored in stub mode.
            jwks_timeout: Timeout for the async JWKS HTTP fetch. A plain number
                is applied to all httpx phases (connect/read/write/pool); pass an
                ``httpx.Timeout`` for finer control. Defaults to a tight
                connect=2s / read=5s so a hung endpoint fails fast rather than
                stalling concurrent validations behind the single-flight lock.
                Ignored in stub mode.
        """
        self.jwks_url = jwks_url
        self.audience = audience
        self.algorithms = algorithms or ["RS256"]
        self.jwks_cache_lifespan = jwks_cache_lifespan
        self.jwks_timeout = jwks_timeout

        if dev_mode and not stub_mode:
            logger.warning(
                "AuthService 'dev_mode' is deprecated; use 'stub_mode'. The "
                "stub mechanism now verifies HS256-signed JWTs instead of "
                "looking tokens up in a dict."
            )
            stub_mode = True
        self.stub_mode = stub_mode
        # Backwards-compatible attribute some callers may still read.
        self.dev_mode = stub_mode

        # JWKS cache state (production mode only). Populated lazily on the first
        # validation and refreshed once the lifespan expires. Guarded by an
        # asyncio.Lock so concurrent requests that miss the cache trigger a
        # single fetch (single-flight) rather than a thundering herd.
        self._jwks_headers = custom_headers or {"User-agent": "newsquawk-service"}
        self._jwks_by_kid: Optional[Dict[str, PyJWK]] = None
        self._jwks_fetched_at: float = 0.0
        self._jwks_lock = asyncio.Lock()

        if stub_mode:
            # Stub mode: verify HS256 tokens with a shared secret instead of
            # fetching signing keys from a JWKS endpoint. No JWKS fetch.
            self.stub_secret = stub_secret or DEFAULT_STUB_SECRET
            self.algorithms = [STUB_ALGORITHM]
            logger.warning(
                "AuthService initialized in STUB MODE — tokens are verified "
                "against a shared HS256 secret, NOT Keycloak. Do not use this "
                "in production."
            )
            return

        if not jwks_url:
            raise ValueError("jwks_url is required when stub_mode is False")

        if not audience:
            logger.warning(
                "AuthService initialized without an audience — the token 'aud' "
                "claim will NOT be validated. Signature and expiry are still "
                "verified."
            )

    async def verify_and_decode_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token.

        In production this:
        1. Fetches the signing key from the JWKS endpoint (async, off the event
           loop's critical path — the HTTP fetch is awaited via httpx and the
           result is cached, so concurrent requests are not blocked)
        2. Verifies the RS256 signature, audience and expiration

        In stub mode the signing key is the shared HS256 secret instead of a
        JWKS key; signature, audience and expiration are still verified.

        Args:
            token: The JWT token string to verify and decode

        Returns:
            Dict containing the decoded token claims

        Raises:
            HTTPException: 401 if token is invalid, expired, or verification fails
        """
        try:
            if self.stub_mode:
                # Stub mode: verify the HS256 signature with the shared secret.
                key: Any = self.stub_secret
                algorithms = self.algorithms
            else:
                # Resolve the signing key for this token's `kid` from the JWKS,
                # awaiting an async fetch on a cache miss so the event loop stays
                # free for other requests.
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get("kid")
                key = (await self._get_signing_key(kid)).key
                algorithms = self.algorithms

            # Decode and verify the token. Audience is validated only when an
            # audience was configured; otherwise verify_aud is disabled so that
            # tokens carrying an aud claim are not rejected outright.
            decoded_token = jwt.decode(
                token,
                key,
                algorithms=algorithms,
                audience=self.audience,
                options={
                    "verify_exp": True,
                    "verify_aud": self.audience is not None,
                },
            )

            return decoded_token

        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidAudienceError:
            logger.warning(f"Invalid audience. Expected: {self.audience}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token audience",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except JWKSUnavailableError as e:
            # Upstream identity provider is unreachable/misbehaving. This is not
            # the client's fault, so surface a 503 (retryable) rather than a 401.
            logger.error(f"JWKS endpoint unavailable: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service temporarily unavailable",
            )
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def _cached_signing_key(self, kid: Optional[str]) -> Optional[PyJWK]:
        """
        Return the cached signing key for ``kid`` if the cache is warm and valid.

        Returns None when the cache is empty, expired, or does not contain the
        requested ``kid`` (e.g. after a key rotation), signalling the caller to
        refresh under the lock.
        """
        if self._jwks_by_kid is None:
            return None
        if time.monotonic() > self._jwks_fetched_at + self.jwks_cache_lifespan:
            return None
        return self._jwks_by_kid.get(kid)

    async def _get_signing_key(self, kid: Optional[str]) -> PyJWK:
        """
        Resolve the JWKS signing key for a token's ``kid``, fetching if needed.

        Uses a double-checked lock so that only one coroutine performs the async
        JWKS fetch on a cache miss (single-flight); the rest await the lock and
        reuse the freshly cached result. The HTTP fetch is awaited via httpx, so
        the event loop is never blocked.

        Args:
            kid: The ``kid`` (key id) from the token's unverified header.

        Returns:
            The matching PyJWK signing key.

        Raises:
            jwt.PyJWKClientError: If no key matching ``kid`` exists even after a
                refresh (mapped to a 401 by the caller).
        """
        key = self._cached_signing_key(kid)
        if key is not None:
            return key

        async with self._jwks_lock:
            # Re-check: another coroutine may have refreshed while we waited.
            key = self._cached_signing_key(kid)
            if key is not None:
                return key

            await self._refresh_jwks()

            key = (self._jwks_by_kid or {}).get(kid)
            if key is None:
                raise jwt.PyJWKClientError(
                    f'Unable to find a signing key that matches: "{kid}"'
                )
            return key

    async def _refresh_jwks(self) -> None:
        """
        Fetch the JWKS from ``jwks_url`` and rebuild the ``kid`` -> key cache.

        Called only while holding ``self._jwks_lock``. On a network/parse error
        a :class:`JWKSUnavailableError` is raised and the existing cache is left
        untouched — a transient failure never wipes a previously good cache, and
        the caller maps it to an HTTP 503 rather than a 401.
        """
        try:
            async with httpx.AsyncClient(timeout=self.jwks_timeout) as client:
                response = await client.get(self.jwks_url, headers=self._jwks_headers)
                response.raise_for_status()
                data = response.json()
            jwk_set = PyJWKSet.from_dict(data)
        except (httpx.HTTPError, ValueError, jwt.PyJWTError) as e:
            # Network failure, timeout, non-2xx response, invalid JSON, or an
            # unusable key set — all upstream problems, surfaced as 503.
            raise JWKSUnavailableError(
                f"Failed to fetch JWKS from {self.jwks_url}: {e}"
            ) from e

        self._jwks_by_kid = {
            jwk.key_id: jwk
            for jwk in jwk_set.keys
            if jwk.key_id and jwk.public_key_use in ("sig", None)
        }
        self._jwks_fetched_at = time.monotonic()
        logger.debug(
            "Refreshed JWKS from %s (%d signing key(s))",
            self.jwks_url,
            len(self._jwks_by_kid),
        )

    def extract_client_roles(self, token_data: Dict[str, Any], client: str) -> list[str]:
        """
        Extract a specific client's roles from the decoded token.

        Reads token_data["resource_access"][client]["roles"]. The client is
        chosen explicitly by the caller and is independent of the token
        audience (which is only used to validate the ``aud`` claim).

        Args:
            token_data: Decoded JWT token claims
            client: Keycloak client ID whose roles to read (e.g.
                "mobile-notifications")

        Returns:
            List of client role strings assigned to the user
        """
        try:
            resource_access = token_data.get("resource_access", {})
            client_access = resource_access.get(client, {})
            return client_access.get("roles", [])
        except (KeyError, TypeError, AttributeError):
            logger.warning(f"Unable to extract client roles for '{client}' from token")
            return []

    def extract_realm_roles(self, token_data: Dict[str, Any]) -> list[str]:
        """
        Extract realm-level roles from the decoded token.

        Reads token_data["realm_access"]["roles"].

        Args:
            token_data: Decoded JWT token claims

        Returns:
            List of realm role strings assigned to the user
        """
        try:
            realm_access = token_data.get("realm_access", {})
            return realm_access.get("roles", [])
        except (KeyError, TypeError, AttributeError):
            logger.warning("Unable to extract realm roles from token")
            return []

    def verify_client_role(
        self, token_data: Dict[str, Any], client: str, required_role: str
    ) -> bool:
        """
        Check if the user has a specific role on a specific client.

        Args:
            token_data: Decoded JWT token claims
            client: Keycloak client ID to check roles against
            required_role: The role name to check for

        Returns:
            True if user has the client role, False otherwise
        """
        return required_role in self.extract_client_roles(token_data, client)

    def verify_any_client_role(
        self, token_data: Dict[str, Any], client: str, allowed_roles: list[str]
    ) -> bool:
        """
        Check if the user has any of the specified roles on a specific client.

        Args:
            token_data: Decoded JWT token claims
            client: Keycloak client ID to check roles against
            allowed_roles: List of acceptable role names

        Returns:
            True if user has at least one of the client roles, False otherwise
        """
        user_roles = self.extract_client_roles(token_data, client)
        return any(role in user_roles for role in allowed_roles)

    def verify_realm_role(self, token_data: Dict[str, Any], required_role: str) -> bool:
        """
        Check if the user has a specific realm-level role.

        Args:
            token_data: Decoded JWT token claims
            required_role: The realm role name to check for

        Returns:
            True if user has the realm role, False otherwise
        """
        return required_role in self.extract_realm_roles(token_data)

    def verify_any_realm_role(
        self, token_data: Dict[str, Any], allowed_roles: list[str]
    ) -> bool:
        """
        Check if the user has any of the specified realm-level roles.

        Args:
            token_data: Decoded JWT token claims
            allowed_roles: List of acceptable realm role names

        Returns:
            True if user has at least one of the realm roles, False otherwise
        """
        user_roles = self.extract_realm_roles(token_data)
        return any(role in user_roles for role in allowed_roles)

    def extract_user_id(self, token_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract the user ID from the token.

        Args:
            token_data: Decoded JWT token claims

        Returns:
            User ID string or None if not found
        """
        return token_data.get("sub")

    def extract_username(self, token_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract the username from the token.

        Args:
            token_data: Decoded JWT token claims

        Returns:
            Username string or None if not found
        """
        return token_data.get("preferred_username") or token_data.get("username")

    def extract_email(self, token_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract the email from the token.

        Args:
            token_data: Decoded JWT token claims

        Returns:
            Email string or None if not found
        """
        return token_data.get("email")

    def extract_client_id(self, token_data: Dict[str, Any]) -> Optional[str]:
        """
        Extract the calling client's ID from the token.

        For a service-account (client credentials) token this is the client
        that authenticated. Reads the ``azp`` (authorized party) claim first,
        falling back to ``clientId``/``client_id`` for setups that expose it.

        Args:
            token_data: Decoded JWT token claims

        Returns:
            Client ID string or None if not present
        """
        return (
            token_data.get("azp")
            or token_data.get("clientId")
            or token_data.get("client_id")
        )

    def is_service_account(self, token_data: Dict[str, Any]) -> bool:
        """
        Determine whether the token belongs to a Keycloak service account.

        Keycloak issues client-credentials tokens with a
        ``preferred_username`` of the form ``service-account-<client-id>``.
        This is the reliable marker used here; the ``azp`` claim alone is not
        sufficient because interactive-user tokens also carry it.

        Args:
            token_data: Decoded JWT token claims

        Returns:
            True if the token represents a service account, False otherwise
        """
        username = token_data.get("preferred_username") or ""
        return username.startswith("service-account-")
