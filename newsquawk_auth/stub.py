"""Stub (fake-Keycloak) identity provider for local development and tests.

In production, tokens are minted by Keycloak and validated by
:class:`~newsquawk_auth.service.AuthService` against a JWKS endpoint. For local
development there is often no Keycloak available. This module provides a tiny,
self-contained stand-in that:

* loads users, bcrypt password hashes and role assignments from a YAML file
  (a bundled sample is used when none is supplied);
* verifies a username/password against those hashes; and
* mints a **real** HS256-signed JWT whose claims mirror a Keycloak token
  (``sub``, ``preferred_username``, ``email``, ``realm_access.roles`` ...).

The token is then validated by ``AuthService(stub_mode=True)`` exactly as a
production token would be — same dependencies, same role checks — only the
trust root differs (a shared symmetric secret instead of Keycloak's JWKS).

Because issuing and verifying stub tokens must agree on claim shape, algorithm
and secret, both halves live here in the library rather than being
reimplemented per service. This module is optional: it requires the ``stub``
extra (``bcrypt`` and ``PyYAML``)::

    pip install "newsquawk-auth[stub]"

Never enable any of this in production.
"""

import logging
import time
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    import bcrypt
    import yaml
except ImportError as exc:  # pragma: no cover - exercised only without extra
    raise ImportError(
        "newsquawk_auth.stub requires the 'stub' extra. Install it with:\n"
        "    pip install \"newsquawk-auth[stub]\""
    ) from exc

import jwt
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from newsquawk_auth.service import DEFAULT_STUB_SECRET, STUB_ALGORITHM

logger = logging.getLogger(__name__)

# Bundled sample data file, resolved as a package resource so it works whether
# the package is installed or run from a checkout.
_SAMPLE_DATA_PACKAGE = "newsquawk_auth"
_SAMPLE_DATA_NAME = "stub_users.yaml"

# Defaults chosen so a stub token validates against AuthService(stub_mode=True)
# with no extra configuration. Audience is left unset by default so aud is not
# validated unless a service explicitly opts in.
DEFAULT_STUB_ISSUER = "newsquawk-stub"
DEFAULT_STUB_AUDIENCE = "dev-client"
DEFAULT_STUB_TTL_SECONDS = 3600


class StubAuthError(Exception):
    """Raised when stub authentication fails (bad credentials / unknown user)."""


class StubIdentityProvider:
    """
    A minimal fake-Keycloak that issues HS256 tokens from a YAML user file.

    Args:
        data_path: Path to a YAML file of the documented shape (``users`` and
            ``roles``). When ``None``, the bundled sample data is used and a
            warning is logged.
        secret: HS256 secret used to sign tokens. Must match the secret the
            verifying :class:`~newsquawk_auth.service.AuthService` uses.
            Defaults to :data:`~newsquawk_auth.service.DEFAULT_STUB_SECRET`.
        issuer: ``iss`` claim placed on issued tokens.
        audience: ``aud`` claim placed on issued tokens. A verifier only
            enforces it if configured with a matching ``audience``.
        ttl_seconds: Token lifetime; sets the ``exp`` claim.
    """

    def __init__(
        self,
        data_path: Optional[Union[str, Path]] = None,
        secret: str = DEFAULT_STUB_SECRET,
        issuer: str = DEFAULT_STUB_ISSUER,
        audience: Optional[str] = DEFAULT_STUB_AUDIENCE,
        ttl_seconds: int = DEFAULT_STUB_TTL_SECONDS,
    ):
        self.secret = secret
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds

        data = self._load_data(data_path)
        # Index users by both username and id for flexible lookup.
        self._users_by_username: Dict[str, Dict[str, Any]] = {}
        self._users_by_id: Dict[str, Dict[str, Any]] = {}
        for entry in data.get("users") or []:
            username = entry["user"]
            user_id = entry["id"]
            record = {
                "id": user_id,
                "username": username,
                "password_hash": entry["password_hash"],
                # Treat a username containing "@" as an email address.
                "email": username if "@" in username else None,
            }
            self._users_by_username[username] = record
            self._users_by_id[user_id] = record

        # Invert the role map (role -> [user_id]) into (user_id -> [role]).
        self._realm_roles_by_id: Dict[str, List[str]] = {}
        for role, member_ids in (data.get("roles") or {}).items():
            for user_id in member_ids or []:
                self._realm_roles_by_id.setdefault(user_id, []).append(role)

        logger.warning(
            "StubIdentityProvider ready with %d stub user(s) — HS256 tokens, "
            "local development only.",
            len(self._users_by_username),
        )

    def _load_data(
        self, data_path: Optional[Union[str, Path]]
    ) -> Dict[str, Any]:
        """Load YAML data from ``data_path`` or the bundled sample."""
        if data_path is None:
            logger.warning(
                "StubIdentityProvider using the BUNDLED SAMPLE users file. "
                "Supply data_path to use your own stub users."
            )
            text = (
                resources.files(_SAMPLE_DATA_PACKAGE)
                .joinpath(_SAMPLE_DATA_NAME)
                .read_text(encoding="utf-8")
            )
        else:
            text = Path(data_path).read_text(encoding="utf-8")
        parsed = yaml.safe_load(text) or {}
        if not isinstance(parsed, dict):
            raise ValueError("Stub data file must be a YAML mapping")
        return parsed

    def realm_roles_for(self, user_id: str) -> List[str]:
        """Return the realm roles assigned to the given user id."""
        return list(self._realm_roles_by_id.get(user_id, []))

    def authenticate(self, username: str, password: str) -> str:
        """
        Verify credentials and return a signed HS256 token.

        Args:
            username: The ``user`` value from the data file.
            password: Plaintext password, checked against the stored bcrypt hash.

        Returns:
            A signed HS256 JWT string.

        Raises:
            StubAuthError: If the user is unknown or the password is wrong.
        """
        record = self._users_by_username.get(username)
        # Always run bcrypt to keep timing roughly uniform for unknown users.
        stored_hash = (
            record["password_hash"]
            if record is not None
            else "$2b$12$" + "." * 53
        )
        try:
            ok = bcrypt.checkpw(
                password.encode("utf-8"), stored_hash.encode("utf-8")
            )
        except ValueError:
            ok = False
        if record is None or not ok:
            raise StubAuthError("Invalid username or password")
        return self._issue(record)

    def issue_token(self, user: str) -> str:
        """
        Issue a token for a user without a password (tests/tooling).

        Args:
            user: A username or user id present in the data file.

        Raises:
            StubAuthError: If no such user exists.
        """
        record = self._users_by_username.get(user) or self._users_by_id.get(user)
        if record is None:
            raise StubAuthError(f"Unknown stub user: {user}")
        return self._issue(record)

    def _issue(self, record: Dict[str, Any]) -> str:
        """Build and sign the Keycloak-shaped claims for a user record."""
        now = int(time.time())
        claims: Dict[str, Any] = {
            "sub": record["id"],
            "preferred_username": record["username"],
            "iss": self.issuer,
            "iat": now,
            "exp": now + self.ttl_seconds,
            "realm_access": {"roles": self.realm_roles_for(record["id"])},
        }
        if self.audience is not None:
            claims["aud"] = self.audience
        if record.get("email"):
            claims["email"] = record["email"]
        return jwt.encode(claims, self.secret, algorithm=STUB_ALGORITHM)


class StubLoginRequest(BaseModel):
    """JSON body for the stub login endpoint."""

    username: str
    password: str


class StubTokenResponse(BaseModel):
    """Token response from the stub login endpoint (OAuth2-ish shape)."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


def build_stub_login_router(
    provider: StubIdentityProvider,
    path: str = "/dev/login",
    tags: Optional[List[str]] = None,
) -> APIRouter:
    """
    Build a FastAPI router exposing a stub login endpoint.

    The endpoint accepts ``{"username", "password"}`` and returns a signed
    HS256 token to use as a normal bearer token. Mounting it is the consuming
    app's decision — the library never forces the route on you::

        from newsquawk_auth.stub import StubIdentityProvider, build_stub_login_router

        provider = StubIdentityProvider()  # bundled sample users
        app.include_router(build_stub_login_router(provider))

    Args:
        provider: The identity provider that verifies credentials and mints
            tokens.
        path: Route path for the login endpoint.
        tags: Optional OpenAPI tags for the route.

    Returns:
        A configured :class:`fastapi.APIRouter`.
    """
    router = APIRouter()

    @router.post(path, response_model=StubTokenResponse, tags=tags)
    async def stub_login(body: StubLoginRequest) -> StubTokenResponse:
        try:
            token = provider.authenticate(body.username, body.password)
        except StubAuthError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return StubTokenResponse(
            access_token=token, expires_in=provider.ttl_seconds
        )

    return router
