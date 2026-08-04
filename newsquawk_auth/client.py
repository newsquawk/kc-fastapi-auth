"""Caller-side helpers for Keycloak service-account authentication.

These utilities let a backend app (e.g. FastAPI) obtain an OAuth2 access
token using the *client credentials* grant against Keycloak, then attach it
as a bearer token to outgoing requests to another service. The receiving
service validates the token with :class:`~newsquawk_auth.service.AuthService`
exactly as it would a user token.

Typical usage::

    import httpx
    from newsquawk_auth import ServiceAccountTokenProvider

    provider = ServiceAccountTokenProvider(
        token_url=settings.keycloak_token_url,   # .../realms/<realm>/protocol/openid-connect/token
        client_id=settings.service_client_id,
        client_secret=settings.service_client_secret,
    )

    # Async (recommended inside FastAPI)
    async with httpx.AsyncClient(auth=provider.auth()) as client:
        resp = await client.get("https://other-service/internal/thing")

    # Sync
    resp = httpx.get("https://other-service/internal/thing", auth=provider.auth())
"""

import asyncio
import logging
import threading
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class ServiceAccountError(Exception):
    """Raised when a service-account token cannot be obtained."""


class ServiceAccountTokenProvider:
    """
    Obtains and caches Keycloak service-account access tokens.

    Uses the OAuth2 ``client_credentials`` grant. The most recently obtained
    token is cached in memory and reused until it is within ``refresh_margin``
    seconds of expiry, at which point a fresh token is fetched. Both a
    synchronous (:meth:`get_token`) and an asynchronous
    (:meth:`get_token_async`) accessor are provided; each guards fetches with
    its own lock so concurrent callers trigger at most one network request.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: Optional[str] = None,
        audience: Optional[str] = None,
        refresh_margin: float = 30.0,
        timeout: float = 10.0,
        verify: bool = True,
    ):
        """
        Args:
            token_url: Keycloak token endpoint, e.g.
                ``https://kc/realms/<realm>/protocol/openid-connect/token``.
            client_id: The confidential client's ID (must have service
                accounts enabled in Keycloak).
            client_secret: The client's secret.
            scope: Optional space-separated scopes to request.
            audience: Optional ``audience`` form parameter. Useful when the
                receiving service validates a specific ``aud`` claim; Keycloak
                must be configured (e.g. via an audience mapper) to honour it.
            refresh_margin: Seconds before actual expiry at which the cached
                token is considered stale and refreshed. Defaults to 30.
            timeout: Per-request timeout in seconds for the token endpoint.
            verify: TLS verification passed through to httpx. Set False only
                for local/dev Keycloak with self-signed certs.
        """
        if not token_url:
            raise ValueError("token_url is required")
        if not client_id:
            raise ValueError("client_id is required")
        if not client_secret:
            raise ValueError("client_secret is required")

        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.audience = audience
        self.refresh_margin = refresh_margin
        self.timeout = timeout
        self.verify = verify

        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0
        self._sync_lock = threading.Lock()
        self._async_lock = asyncio.Lock()

    def _request_data(self) -> dict:
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if self.scope:
            data["scope"] = self.scope
        if self.audience:
            data["audience"] = self.audience
        return data

    def _is_valid(self) -> bool:
        """Whether the cached token exists and is not within the refresh margin."""
        return (
            self._access_token is not None
            and time.monotonic() < self._expires_at - self.refresh_margin
        )

    def _store(self, payload: dict) -> str:
        """Cache the token from a token-endpoint response and return it."""
        token = payload.get("access_token")
        if not token:
            raise ServiceAccountError(
                "Token endpoint response did not contain an access_token"
            )
        # Default to a short lifetime if expires_in is absent so we re-fetch soon
        # rather than caching an unbounded token.
        expires_in = float(payload.get("expires_in", 60))
        self._access_token = token
        self._expires_at = time.monotonic() + expires_in
        return token

    @staticmethod
    def _raise_for_status(exc: httpx.HTTPStatusError) -> None:
        """Translate an HTTP error from the token endpoint into a clear error."""
        detail = exc.response.text
        raise ServiceAccountError(
            f"Failed to obtain service-account token "
            f"({exc.response.status_code}): {detail}"
        ) from exc

    def get_token(self, force_refresh: bool = False) -> str:
        """
        Return a valid access token (synchronous), fetching one if needed.

        Args:
            force_refresh: If True, bypass the cache and fetch a new token.
        """
        if not force_refresh and self._is_valid():
            return self._access_token  # type: ignore[return-value]

        with self._sync_lock:
            # Re-check inside the lock in case another thread just refreshed.
            if not force_refresh and self._is_valid():
                return self._access_token  # type: ignore[return-value]
            try:
                resp = httpx.post(
                    self.token_url,
                    data=self._request_data(),
                    timeout=self.timeout,
                    verify=self.verify,
                )
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                self._raise_for_status(e)
            except httpx.HTTPError as e:
                raise ServiceAccountError(
                    f"Request to token endpoint failed: {e}"
                ) from e
            return self._store(resp.json())

    async def get_token_async(self, force_refresh: bool = False) -> str:
        """
        Return a valid access token (asynchronous), fetching one if needed.

        Args:
            force_refresh: If True, bypass the cache and fetch a new token.
        """
        if not force_refresh and self._is_valid():
            return self._access_token  # type: ignore[return-value]

        async with self._async_lock:
            if not force_refresh and self._is_valid():
                return self._access_token  # type: ignore[return-value]
            try:
                async with httpx.AsyncClient(
                    timeout=self.timeout, verify=self.verify
                ) as client:
                    resp = await client.post(
                        self.token_url, data=self._request_data()
                    )
                    resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                self._raise_for_status(e)
            except httpx.HTTPError as e:
                raise ServiceAccountError(
                    f"Request to token endpoint failed: {e}"
                ) from e
            return self._store(resp.json())

    def auth(self) -> "ServiceAccountAuth":
        """Return an :class:`httpx.Auth` that injects this provider's token."""
        return ServiceAccountAuth(self)


class ServiceAccountAuth(httpx.Auth):
    """
    httpx auth flow that attaches a service-account bearer token.

    Works with both sync (``httpx.Client``) and async (``httpx.AsyncClient``)
    requests, sourcing the token from a :class:`ServiceAccountTokenProvider`.
    On a 401 response it forces a single token refresh and retries once, which
    covers the case where the cached token was revoked or the signing keys
    rotated before the local expiry elapsed.
    """

    def __init__(self, provider: ServiceAccountTokenProvider):
        self._provider = provider

    def sync_auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self._provider.get_token()}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = (
                f"Bearer {self._provider.get_token(force_refresh=True)}"
            )
            yield request

    async def async_auth_flow(self, request):
        token = await self._provider.get_token_async()
        request.headers["Authorization"] = f"Bearer {token}"
        response = yield request
        if response.status_code == 401:
            token = await self._provider.get_token_async(force_refresh=True)
            request.headers["Authorization"] = f"Bearer {token}"
            yield request
