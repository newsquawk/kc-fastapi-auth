# Newsquawk Auth Package

Shared authentication package for Newsquawk services using JWT/JWKS token validation.

## Installation

Install this package directly from the public git repository, pinned to release `v0.0.1`.

Using pipenv:

```bash
pipenv install git+https://github.com/newsquawk/kc-fastapi-auth.git@v0.0.1#egg=newsquawk-auth
```

Or with pip:

```bash
pip install git+https://github.com/newsquawk/kc-fastapi-auth.git@v0.0.1
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

## Dev Mode (stub users, no Keycloak)

For local development and tests you can run without a real Keycloak/JWKS
endpoint. In dev mode, **JWT signatures are not verified** — instead the bearer
token string is used to look up a stub user you register up front.

```python
from newsquawk_auth import AuthService, AuthDependencies

auth_service = AuthService(
    dev_mode=True,
    dev_users={
        # bearer token string -> stub user spec
        "admin-token": {
            "username": "alice",
            "email": "alice@example.com",
            "roles": ["admin", "access-internal"],
        },
        "external-token": {
            "username": "bob",
            "roles": ["access-external"],
        },
    },
)
auth_deps = AuthDependencies(auth_service)
```

Routes and dependencies are used exactly as in production — nothing else
changes. Call a protected endpoint with the stub token as a normal bearer
token:

```bash
curl -H "Authorization: Bearer admin-token" http://localhost:8000/protected
```

Each stub user spec accepts:

- `roles` — list of role strings (nested under `resource_access[audience]` so
  `has_role` / `has_any_role` work identically to a real token)
- `username` — maps to `preferred_username`
- `email`
- `user_id` / `sub` — defaults to `username` if omitted
- `claims` — optional dict of extra/raw claims merged into the token data

In dev mode `jwks_url` is not needed and `audience` defaults to `"dev-client"`.
When `dev_users` is provided, an unrecognised token returns `401`.

If you omit `dev_users` entirely, token verification is **skipped completely** —
any token (or none) resolves to a default stub user (`sub="dev-user"`, no
roles). Handy for the fastest possible local setup:

```python
auth_service = AuthService(dev_mode=True)  # accept anything as "dev-user"
```

> ⚠️ **Never enable `dev_mode` in production.** Gate it behind an environment
> flag in the consuming service, e.g. `dev_mode=settings.auth_dev_mode`.

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
