"""Authentication service using JWT and JWKS for token validation."""

import logging
from typing import Any, Dict, Optional

import jwt
from jwt import PyJWKClient
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class AuthService:
    """
    Service class for handling JWT authentication with remote JWKS certificates.

    This service validates JWT tokens using PyJWKClient to fetch and cache
    signing keys from a remote JWKS endpoint (e.g., Keycloak).
    """

    def __init__(
        self,
        jwks_url: Optional[str] = None,
        audience: Optional[str] = None,
        algorithms: Optional[list[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        dev_mode: bool = False,
        dev_users: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        """
        Initialize the authentication service.

        Args:
            jwks_url: URL to the JWKS endpoint (e.g., Keycloak certs endpoint).
                Required unless dev_mode is True.
            audience: Expected audience (aud) claim in the JWT token. Optional.
                When set, the token's aud claim must be present and match. When
                None (and not in dev mode), audience validation is disabled
                entirely — signature and expiry are still verified. Defaults to
                "dev-client" in dev mode.
            algorithms: List of allowed signing algorithms (default: ["RS256"])
            custom_headers: Optional custom headers for JWKS client requests
            dev_mode: If True, JWT signatures are NOT verified. Instead, the
                bearer token is looked up in dev_users to resolve a stub user.
                NEVER enable this in production.
            dev_users: Mapping of bearer-token string -> stub user spec. Each
                spec may contain "user_id"/"sub", "username", "email",
                "realm_roles" (a list), "client_roles" (a dict of
                client -> list of roles), and an optional "claims" dict for
                extra/raw claims. Only used when dev_mode is True. If
                omitted/empty, token verification is skipped entirely and any
                token (including none) resolves to a default stub user.
        """
        self.jwks_url = jwks_url
        self.audience = audience
        self.algorithms = algorithms or ["RS256"]
        self.dev_mode = dev_mode

        if dev_mode:
            # In dev mode we short-circuit JWKS verification entirely.
            self.audience = audience or "dev-client"
            self.dev_users = self._build_dev_users(dev_users or {})
            self.jwks_client = None
            logger.warning(
                "AuthService initialized in DEV MODE — JWT signatures are NOT "
                "verified. Do not use this in production."
            )
            return

        if not jwks_url:
            raise ValueError("jwks_url is required when dev_mode is False")

        if not audience:
            logger.warning(
                "AuthService initialized without an audience — the token 'aud' "
                "claim will NOT be validated. Signature and expiry are still "
                "verified."
            )

        # Initialize PyJWKClient with optional custom headers
        headers = custom_headers or {"User-agent": "newsquawk-service"}
        self.jwks_client = PyJWKClient(jwks_url, headers=headers)

    def _build_dev_users(
        self, dev_users: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Resolve each stub user spec into Keycloak-shaped token claims."""
        return {
            token: self._spec_to_claims(spec) for token, spec in dev_users.items()
        }

    def _spec_to_claims(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build decoded-token claims from a stub user spec.

        Realm roles are nested under realm_access[roles] and client roles under
        resource_access[client][roles], mirroring a real Keycloak token so the
        extract_* / verify_* methods work identically.

        Spec keys:
            user_id / sub, username, email
            realm_roles: list[str] -> realm_access.roles
            client_roles: dict[client -> list[str]] -> resource_access[client].roles
            claims: dict of extra/raw claims merged in last
        """
        claims: Dict[str, Any] = {
            "sub": spec.get("user_id") or spec.get("sub") or spec.get("username", "dev-user"),
            "preferred_username": spec.get("username"),
            "email": spec.get("email"),
        }
        realm_roles = spec.get("realm_roles")
        if realm_roles:
            claims["realm_access"] = {"roles": list(realm_roles)}
        client_roles = spec.get("client_roles")
        if client_roles:
            claims["resource_access"] = {
                client: {"roles": list(roles)} for client, roles in client_roles.items()
            }
        # Allow arbitrary extra/raw claims to be merged in or override defaults.
        claims.update(spec.get("claims", {}))
        return claims

    async def verify_and_decode_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT token using remote JWKS certificates.

        This method:
        1. Fetches the signing key from the JWKS endpoint
        2. Verifies the token signature
        3. Validates the audience and expiration
        4. Returns the decoded token claims

        Args:
            token: The JWT token string to verify and decode

        Returns:
            Dict containing the decoded token claims

        Raises:
            HTTPException: 401 if token is invalid, expired, or verification fails
        """
        if self.dev_mode:
            logger.warning(
                "DEV MODE auth: resolving stub user from token without "
                "signature verification"
            )
            # No registry configured -> skip verification, accept any token
            # (including none) and return a default stub user.
            if not self.dev_users:
                return self._spec_to_claims({})
            if token in self.dev_users:
                return self.dev_users[token]
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unknown dev user token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            # Get the signing key from the JWKS endpoint
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and verify the token. Audience is validated only when an
            # audience was configured; otherwise verify_aud is disabled so that
            # tokens carrying an aud claim are not rejected outright.
            decoded_token = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
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
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
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
