"""FastAPI dependencies for authentication and authorization."""

from typing import Annotated, Callable, Dict, Any, Optional
from functools import wraps
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from newsquawk_auth.service import AuthService


# HTTP Bearer scheme for extracting tokens from Authorization header
bearer_scheme = HTTPBearer()


async def extract_token(
    auth: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> str:
    """
    Extract JWT token from Authorization header.

    Expects header format: Authorization: Bearer <token>

    Args:
        auth: HTTP Authorization credentials from bearer_scheme

    Returns:
        The extracted JWT token string
    """
    return auth.credentials


class CurrentUser:
    """
    Model representing the authenticated user with extracted claims.

    This class provides convenient access to common user attributes
    extracted from the JWT token.
    """

    def __init__(self, token_data: Dict[str, Any], auth_service: AuthService):
        """
        Initialize CurrentUser from decoded token data.

        Args:
            token_data: Decoded JWT token claims
            auth_service: AuthService instance for role verification
        """
        self._token_data = token_data
        self._auth_service = auth_service

    @property
    def user_id(self) -> Optional[str]:
        """User's unique identifier (sub claim)."""
        return self._auth_service.extract_user_id(self._token_data)

    @property
    def username(self) -> Optional[str]:
        """User's username."""
        return self._auth_service.extract_username(self._token_data)

    @property
    def email(self) -> Optional[str]:
        """User's email address."""
        return self._auth_service.extract_email(self._token_data)

    @property
    def realm_roles(self) -> list[str]:
        """List of the user's realm-level roles."""
        return self._auth_service.extract_realm_roles(self._token_data)

    def client_roles(self, client: str) -> list[str]:
        """List of the user's roles on a specific client."""
        return self._auth_service.extract_client_roles(self._token_data, client)

    @property
    def token_data(self) -> Dict[str, Any]:
        """Raw decoded token data for custom claim access."""
        return self._token_data

    def has_realm_role(self, role: str) -> bool:
        """Check if user has a specific realm-level role."""
        return self._auth_service.verify_realm_role(self._token_data, role)

    def has_any_realm_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified realm-level roles."""
        return self._auth_service.verify_any_realm_role(self._token_data, roles)

    def has_client_role(self, client: str, role: str) -> bool:
        """Check if user has a specific role on a specific client."""
        return self._auth_service.verify_client_role(self._token_data, client, role)

    def has_any_client_role(self, client: str, roles: list[str]) -> bool:
        """Check if user has any of the specified roles on a specific client."""
        return self._auth_service.verify_any_client_role(self._token_data, client, roles)

    def __repr__(self) -> str:
        return f"CurrentUser(user_id={self.user_id}, username={self.username})"


class AuthDependencies:
    """
    Factory class that creates FastAPI dependencies with an injected AuthService.

    This class provides methods that return configured FastAPI dependency functions
    with the AuthService already bound.

    Usage:
        from newsquawk_auth import AuthService, AuthDependencies

        # Create service and dependencies
        auth_service = AuthService(
            jwks_url=settings.keycloak_jwks_url,
            audience=settings.keycloak_audience,
        )
        auth_deps = AuthDependencies(auth_service)

        # Use in routes
        @app.get("/protected")
        async def protected_route(
            user: Annotated[CurrentUser, Depends(auth_deps.get_current_user())]
        ):
            return {"user_id": user.user_id}

        @app.get("/notifications")
        async def notifications_route(
            _: Annotated[None, Depends(auth_deps.has_client_role("mobile-notifications", "subscriber"))]
        ):
            return {"message": "Subscriber access granted"}

        @app.get("/admin")
        async def admin_route(_: Annotated[None, Depends(auth_deps.has_realm_role("admin"))]):
            return {"message": "Admin access granted"}
    """

    def __init__(self, auth_service: AuthService):
        """
        Initialize with an AuthService instance.

        Args:
            auth_service: Configured AuthService instance
        """
        self.auth_service = auth_service

    def get_token_data(self) -> Callable:
        """
        Create a dependency that validates and returns token data.

        Returns:
            Async dependency function that returns decoded token claims
        """
        auth_service = self.auth_service

        async def _get_token_data(
            token: Annotated[str, Depends(extract_token)],
        ) -> Dict[str, Any]:
            """Validate and decode the JWT token."""
            return await auth_service.verify_and_decode_token(token)

        return _get_token_data

    def get_current_user(self) -> Callable:
        """
        Create a dependency that returns the current authenticated user.

        Returns:
            Async dependency function that returns CurrentUser
        """
        auth_service = self.auth_service
        _get_token_data = self.get_token_data()

        async def _get_current_user(
            token_data: Annotated[Dict[str, Any], Depends(_get_token_data)],
        ) -> CurrentUser:
            """Get the current authenticated user."""
            return CurrentUser(token_data, auth_service)

        return _get_current_user

    def has_client_role(self, client: str, required_role: str) -> Callable:
        """
        Create a dependency that requires a specific role on a specific client.

        The client is chosen explicitly by the caller and is independent of the
        token audience.

        Args:
            client: Keycloak client ID whose roles to check (e.g.
                "mobile-notifications")
            required_role: The role name that the user must have on that client

        Returns:
            Async dependency function that checks for the client role

        Raises:
            HTTPException: 403 if user doesn't have the required client role
        """
        auth_service = self.auth_service
        _get_token_data = self.get_token_data()

        async def _check_client_role(
            token_data: Annotated[Dict[str, Any], Depends(_get_token_data)],
        ) -> None:
            """Check if user has the required client role."""
            if not auth_service.verify_client_role(token_data, client, required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required role '{required_role}' for client '{client}'",
                )

        return _check_client_role

    def has_any_client_role(self, client: str, allowed_roles: list[str]) -> Callable:
        """
        Create a dependency that requires any of the given roles on a client.

        Args:
            client: Keycloak client ID whose roles to check
            allowed_roles: List of acceptable role names on that client

        Returns:
            Async dependency function that returns the user's client roles

        Raises:
            HTTPException: 403 if user has none of the allowed client roles
        """
        auth_service = self.auth_service
        _get_token_data = self.get_token_data()

        async def _check_client_roles(
            token_data: Annotated[Dict[str, Any], Depends(_get_token_data)],
        ) -> list[str]:
            """Check if user has any of the allowed client roles."""
            if not auth_service.verify_any_client_role(token_data, client, allowed_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Missing required roles for client '{client}'. "
                        f"Need one of: {', '.join(allowed_roles)}"
                    ),
                )

            return auth_service.extract_client_roles(token_data, client)

        return _check_client_roles

    def has_realm_role(self, required_role: str) -> Callable:
        """
        Create a dependency that requires a specific realm-level role.

        Args:
            required_role: The realm role name that the user must have

        Returns:
            Async dependency function that checks for the realm role

        Raises:
            HTTPException: 403 if user doesn't have the required realm role
        """
        auth_service = self.auth_service
        _get_token_data = self.get_token_data()

        async def _check_realm_role(
            token_data: Annotated[Dict[str, Any], Depends(_get_token_data)],
        ) -> None:
            """Check if user has the required realm role."""
            if not auth_service.verify_realm_role(token_data, required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required realm role: {required_role}",
                )

        return _check_realm_role

    def has_any_realm_role(self, allowed_roles: list[str]) -> Callable:
        """
        Create a dependency that requires any of the given realm-level roles.

        Args:
            allowed_roles: List of acceptable realm role names

        Returns:
            Async dependency function that returns the user's realm roles

        Raises:
            HTTPException: 403 if user has none of the allowed realm roles
        """
        auth_service = self.auth_service
        _get_token_data = self.get_token_data()

        async def _check_realm_roles(
            token_data: Annotated[Dict[str, Any], Depends(_get_token_data)],
        ) -> list[str]:
            """Check if user has any of the allowed realm roles."""
            if not auth_service.verify_any_realm_role(token_data, allowed_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required realm roles. Need one of: {', '.join(allowed_roles)}",
                )

            return auth_service.extract_realm_roles(token_data)

        return _check_realm_roles


# Convenience functions for backward compatibility and simpler usage
def get_token_data(auth_service: AuthService) -> Callable:
    """
    Create a token data dependency for the given AuthService.

    Args:
        auth_service: Configured AuthService instance

    Returns:
        Async dependency function
    """
    return AuthDependencies(auth_service).get_token_data()


def get_current_user(auth_service: AuthService) -> Callable:
    """
    Create a current user dependency for the given AuthService.

    Args:
        auth_service: Configured AuthService instance

    Returns:
        Async dependency function
    """
    return AuthDependencies(auth_service).get_current_user()


def has_client_role(
    auth_service: AuthService, client: str, required_role: str
) -> Callable:
    """
    Create a client-role check dependency for the given AuthService.

    Args:
        auth_service: Configured AuthService instance
        client: Keycloak client ID whose roles to check
        required_role: The role name that the user must have on that client

    Returns:
        Async dependency function
    """
    return AuthDependencies(auth_service).has_client_role(client, required_role)


def has_any_client_role(
    auth_service: AuthService, client: str, allowed_roles: list[str]
) -> Callable:
    """
    Create a multi-client-role check dependency for the given AuthService.

    Args:
        auth_service: Configured AuthService instance
        client: Keycloak client ID whose roles to check
        allowed_roles: List of acceptable role names on that client

    Returns:
        Async dependency function
    """
    return AuthDependencies(auth_service).has_any_client_role(client, allowed_roles)


def has_realm_role(auth_service: AuthService, required_role: str) -> Callable:
    """
    Create a realm-role check dependency for the given AuthService.

    Args:
        auth_service: Configured AuthService instance
        required_role: The realm role name that the user must have

    Returns:
        Async dependency function
    """
    return AuthDependencies(auth_service).has_realm_role(required_role)


def has_any_realm_role(auth_service: AuthService, allowed_roles: list[str]) -> Callable:
    """
    Create a multi-realm-role check dependency for the given AuthService.

    Args:
        auth_service: Configured AuthService instance
        allowed_roles: List of acceptable realm role names

    Returns:
        Async dependency function
    """
    return AuthDependencies(auth_service).has_any_realm_role(allowed_roles)
