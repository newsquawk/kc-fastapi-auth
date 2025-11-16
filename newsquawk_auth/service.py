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
        jwks_url: str,
        audience: str,
        algorithms: Optional[list[str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize the authentication service.

        Args:
            jwks_url: URL to the JWKS endpoint (e.g., Keycloak certs endpoint)
            audience: Expected audience claim in the JWT token
            algorithms: List of allowed signing algorithms (default: ["RS256"])
            custom_headers: Optional custom headers for JWKS client requests
        """
        self.jwks_url = jwks_url
        self.audience = audience
        self.algorithms = algorithms or ["RS256"]

        # Initialize PyJWKClient with optional custom headers
        headers = custom_headers or {"User-agent": "newsquawk-service"}
        self.jwks_client = PyJWKClient(jwks_url, headers=headers)

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
        try:
            # Get the signing key from the JWKS endpoint
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)

            # Decode and verify the token
            decoded_token = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=self.audience,
                options={"verify_exp": True},
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

    def extract_roles(self, token_data: Dict[str, Any]) -> list[str]:
        """
        Extract user roles from the decoded token.

        This method handles the Keycloak token structure where roles are stored
        in token_data["resource_access"][audience]["roles"].

        Args:
            token_data: Decoded JWT token claims

        Returns:
            List of role strings assigned to the user
        """
        try:
            resource_access = token_data.get("resource_access", {})
            client_access = resource_access.get(self.audience, {})
            roles = client_access.get("roles", [])
            return roles
        except (KeyError, TypeError, AttributeError):
            logger.warning("Unable to extract roles from token")
            return []

    def verify_role(self, token_data: Dict[str, Any], required_role: str) -> bool:
        """
        Check if the user has a specific role.

        Args:
            token_data: Decoded JWT token claims
            required_role: The role name to check for

        Returns:
            True if user has the role, False otherwise
        """
        user_roles = self.extract_roles(token_data)
        return required_role in user_roles

    def verify_any_role(self, token_data: Dict[str, Any], allowed_roles: list[str]) -> bool:
        """
        Check if the user has any of the specified roles.

        Args:
            token_data: Decoded JWT token claims
            allowed_roles: List of acceptable role names

        Returns:
            True if user has at least one of the roles, False otherwise
        """
        user_roles = self.extract_roles(token_data)
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
