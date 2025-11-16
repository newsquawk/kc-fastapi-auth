# Newsquawk Auth Package

Shared authentication package for Newsquawk services using JWT/JWKS token validation.

## Installation

From another service, install this package using pipenv:

```bash
pipenv install -e ../packages/newsquawk-auth
```

Or with pip:

```bash
pip install -e ../packages/newsquawk-auth
```

## Usage

### Method 1: Using AuthDependencies Class (Recommended)

```python
from typing import Annotated
from fastapi import Depends
from newsquawk_auth import AuthService, AuthDependencies, CurrentUser
from settings import settings

# Create the auth service and dependencies
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
    return {"user_id": user.user_id, "username": user.username}

@app.get("/admin")
async def admin_route(_: Annotated[None, Depends(auth_deps.has_role("admin"))]):
    return {"message": "Admin access granted"}

@app.get("/content")
async def content_route(
    user_roles: Annotated[list[str], Depends(auth_deps.has_any_role(["editor", "admin"]))]
):
    return {"roles": user_roles}

@app.get("/data")
async def get_data(
    is_internal: Annotated[bool, Depends(auth_deps.require_internal_or_external())]
):
    if is_internal:
        return {"data": "full_data"}
    return {"data": "limited_data"}
```

### Method 2: Using Convenience Functions

```python
from typing import Annotated
from fastapi import Depends
from newsquawk_auth import (
    AuthService,
    get_current_user,
    has_role,
    has_any_role,
    CurrentUser,
)
from settings import settings

# Create the auth service
auth_service = AuthService(
    jwks_url=settings.keycloak_jwks_url,
    audience=settings.keycloak_audience,
)

# Create dependencies by passing auth_service directly
@app.get("/protected")
async def protected_route(
    user: Annotated[CurrentUser, Depends(get_current_user(auth_service))]
):
    return {"user_id": user.user_id}

@app.get("/admin")
async def admin_route(_: Annotated[None, Depends(has_role(auth_service, "admin"))]):
    return {"message": "Admin access granted"}

@app.get("/content")
async def content_route(
    user_roles: Annotated[list[str], Depends(has_any_role(auth_service, ["editor", "admin"]))]
):
    return {"roles": user_roles}
```

## API Reference

### AuthService

Core service for JWT token validation with JWKS.

- `verify_and_decode_token(token)` - Validate and decode JWT token
- `extract_roles(token_data)` - Extract roles from token claims
- `verify_role(token_data, role)` - Check if user has specific role
- `verify_any_role(token_data, roles)` - Check if user has any of the roles
- `extract_user_id(token_data)` - Get user ID from token
- `extract_username(token_data)` - Get username from token
- `extract_email(token_data)` - Get email from token

### AuthDependencies

Factory class that creates FastAPI dependencies with injected AuthService.

```python
auth_deps = AuthDependencies(auth_service)
```

Methods:
- `get_token_data()` - Returns dependency that validates and returns token claims
- `get_current_user()` - Returns dependency that returns CurrentUser object
- `has_role(role)` - Returns dependency that checks for specific role
- `has_any_role(roles)` - Returns dependency that checks for any of the roles
- `require_internal_or_external()` - Returns dependency for internal/external access check

### CurrentUser

Wrapper class for authenticated user with convenient properties:

- `user_id` - User's unique identifier
- `username` - User's username
- `email` - User's email
- `roles` - List of user's roles
- `token_data` - Raw token claims
- `has_role(role)` - Check for specific role
- `has_any_role(roles)` - Check for any of the roles

### Convenience Functions

These functions accept an AuthService instance and return configured dependencies:

- `get_token_data(auth_service)` - Create token validation dependency
- `get_current_user(auth_service)` - Create current user dependency
- `has_role(auth_service, role)` - Create role check dependency
- `has_any_role(auth_service, roles)` - Create multi-role check dependency
- `require_internal_or_external(auth_service)` - Create internal/external access check
