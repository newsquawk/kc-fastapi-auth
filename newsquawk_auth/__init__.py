"""Newsquawk authentication package for JWT/JWKS token validation."""

from newsquawk_auth.service import AuthService
from newsquawk_auth.deps import (
    bearer_scheme,
    extract_token,
    CurrentUser,
    AuthDependencies,
    # Convenience functions that accept AuthService directly
    get_token_data,
    get_current_user,
    has_role,
    has_any_role,
    require_internal_or_external,
)

__version__ = "0.1.0"

__all__ = [
    "AuthService",
    "AuthDependencies",
    "bearer_scheme",
    "extract_token",
    "CurrentUser",
    # Convenience functions
    "get_token_data",
    "get_current_user",
    "has_role",
    "has_any_role",
    "require_internal_or_external",
]
