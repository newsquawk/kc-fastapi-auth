"""Newsquawk authentication package for JWT/JWKS token validation."""

from newsquawk_auth.service import (
    AuthService,
    DEFAULT_STUB_SECRET,
    JWKSUnavailableError,
)
from newsquawk_auth.client import (
    ServiceAccountTokenProvider,
    ServiceAccountAuth,
    ServiceAccountError,
)
from newsquawk_auth.deps import (
    bearer_scheme,
    extract_token,
    CurrentUser,
    AuthDependencies,
    # Convenience functions that accept AuthService directly
    get_token_data,
    get_current_user,
    has_client_role,
    has_any_client_role,
    has_realm_role,
    has_any_realm_role,
    require_service_account,
)

# Stub (fake-Keycloak) helpers live in newsquawk_auth.stub and require the
# optional "stub" extra (bcrypt, PyYAML). They are intentionally NOT imported
# here so the core install stays lean:
#     from newsquawk_auth.stub import StubIdentityProvider, build_stub_login_router

__version__ = "0.3.1"

__all__ = [
    "AuthService",
    "DEFAULT_STUB_SECRET",
    "JWKSUnavailableError",
    "AuthDependencies",
    # Service-account (client-credentials) caller-side helpers
    "ServiceAccountTokenProvider",
    "ServiceAccountAuth",
    "ServiceAccountError",
    "bearer_scheme",
    "extract_token",
    "CurrentUser",
    # Convenience functions
    "get_token_data",
    "get_current_user",
    "has_client_role",
    "has_any_client_role",
    "has_realm_role",
    "has_any_realm_role",
    "require_service_account",
]
