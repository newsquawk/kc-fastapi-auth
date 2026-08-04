"""Newsquawk authentication package for JWT/JWKS token validation."""

from newsquawk_auth.service import AuthService
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

__version__ = "0.1.1"

__all__ = [
    "AuthService",
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
