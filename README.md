# Newsquawk Auth Package

Shared authentication package for Newsquawk services using JWT/JWKS token validation.

## Installation

Install this package directly from the public git repository, pinned to release `v0.1.0`.

Using pipenv:

```bash
pipenv install git+https://github.com/newsquawk/kc-fastapi-auth.git@v0.1.0#egg=newsquawk-auth
```

Or with pip:

```bash
pip install git+https://github.com/newsquawk/kc-fastapi-auth.git@v0.1.0
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

# Client-level role: require role "subscriber" on the "mobile-notifications" client.
# The client is chosen here explicitly and is independent of the token audience.
@app.get("/notifications")
async def notifications_route(
    _: Annotated[None, Depends(auth_deps.has_client_role("mobile-notifications", "subscriber"))]
):
    return {"message": "Subscriber access granted"}

# Any of several client roles
@app.get("/content")
async def content_route(
    roles: Annotated[list[str], Depends(auth_deps.has_any_client_role("mobile-notifications", ["editor", "admin"]))]
):
    return {"roles": roles}

# Realm-level role
@app.get("/admin")
async def admin_route(_: Annotated[None, Depends(auth_deps.has_realm_role("admin"))]):
    return {"message": "Admin access granted"}
```

### Method 2: Using Convenience Functions

```python
from typing import Annotated
from fastapi import Depends
from newsquawk_auth import (
    AuthService,
    get_current_user,
    has_client_role,
    has_realm_role,
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

@app.get("/notifications")
async def notifications_route(
    _: Annotated[None, Depends(has_client_role(auth_service, "mobile-notifications", "subscriber"))]
):
    return {"message": "Subscriber access granted"}

@app.get("/admin")
async def admin_route(_: Annotated[None, Depends(has_realm_role(auth_service, "admin"))]):
    return {"message": "Admin access granted"}
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
        "subscriber-token": {
            "username": "alice",
            "email": "alice@example.com",
            "realm_roles": ["offline_access"],
            "client_roles": {"mobile-notifications": ["subscriber"]},
        },
        "admin-token": {
            "username": "bob",
            "realm_roles": ["admin"],
        },
    },
)
auth_deps = AuthDependencies(auth_service)
```

Routes and dependencies are used exactly as in production — nothing else
changes. Call a protected endpoint with the stub token as a normal bearer
token:

```bash
curl -H "Authorization: Bearer subscriber-token" http://localhost:8000/notifications
```

Each stub user spec accepts:

- `realm_roles` — list of realm role strings (nested under `realm_access.roles`)
- `client_roles` — dict of `client -> list of roles` (nested under
  `resource_access[client].roles`) so `has_client_role` works per client
- `username` — maps to `preferred_username`
- `email`
- `user_id` / `sub` — defaults to `username` if omitted
- `claims` — optional dict of extra/raw claims merged into the token data

In dev mode `jwks_url` is not needed. When `dev_users` is provided, an
unrecognised token returns `401`.

If you omit `dev_users` entirely, token verification is **skipped completely** —
any token (or none) resolves to a default stub user (`sub="dev-user"`, no
roles). Handy for the fastest possible local setup:

```python
auth_service = AuthService(dev_mode=True)  # accept anything as "dev-user"
```

> ⚠️ **Never enable `dev_mode` in production.** Gate it behind an environment
> flag in the consuming service, e.g. `dev_mode=settings.auth_dev_mode`.

## Realm roles vs. client roles

Keycloak tokens carry two independent sets of roles:

- **Realm roles** — `realm_access.roles` — realm-wide roles not tied to a client.
- **Client roles** — `resource_access[<client>].roles` — roles scoped to a
  specific Keycloak client.

`audience` is used **only** to validate the token's `aud` claim during
verification; it is never used to look up roles. The client whose roles you
check is always passed explicitly at the call site (e.g.
`has_client_role("mobile-notifications", "subscriber")`), so a service can
validate one audience while authorizing against any client's roles.

## Token verification

`verify_and_decode_token` always verifies:

1. **Signature** — the token's signing key is fetched from the JWKS endpoint (by
   `kid`) and the signature is checked (`RS256` by default).
2. **Expiry (`exp`)** — expired tokens are rejected.
3. **Audience (`aud`)** — only when `audience` is configured (see below).

### Optional audience

`audience` is optional. Only `jwks_url` is required (outside dev mode).

- **With `audience` set** — the token must carry an `aud` claim that matches, or
  it is rejected (`MissingRequiredClaimError` / `InvalidAudienceError`).
- **Without `audience`** — audience validation is disabled (`verify_aud=False`),
  so tokens are accepted regardless of their `aud` claim. Signature and expiry
  are still enforced. A warning is logged at init.

```python
# Audience enforced
auth_service = AuthService(jwks_url=settings.keycloak_jwks_url, audience="my-api")

# Audience not checked (e.g. tokens already scoped upstream)
auth_service = AuthService(jwks_url=settings.keycloak_jwks_url)
```

> Note: passing `audience=None` correctly disables the check. Do **not** attempt
> to skip audience by any other means — a plain `audience=None` without
> `verify_aud=False` would instead reject every token that carries an `aud`
> claim (which Keycloak tokens normally do). The library handles this for you.

## Service-to-service auth (Keycloak service accounts)

For machine-to-machine calls — one backend app authenticating to another using
Keycloak service accounts (client-credentials grant), token acquisition/caching
on the caller, and service-account authorization on the receiver — see
**[docs/service-accounts.md](docs/service-accounts.md)**.

## API Reference

### AuthService

Core service for JWT token validation with JWKS.

- `verify_and_decode_token(token)` - Validate and decode JWT token
- `extract_client_roles(token_data, client)` - Roles for a specific client
- `extract_realm_roles(token_data)` - Realm-level roles
- `verify_client_role(token_data, client, role)` - Check a specific client role
- `verify_any_client_role(token_data, client, roles)` - Check any of the client roles
- `verify_realm_role(token_data, role)` - Check a specific realm role
- `verify_any_realm_role(token_data, roles)` - Check any of the realm roles
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
- `has_client_role(client, role)` - Dependency requiring a role on a client
- `has_any_client_role(client, roles)` - Dependency requiring any of a client's roles (returns the client roles)
- `has_realm_role(role)` - Dependency requiring a realm role
- `has_any_realm_role(roles)` - Dependency requiring any of the realm roles (returns the realm roles)

### CurrentUser

Wrapper class for authenticated user with convenient properties:

- `user_id` - User's unique identifier
- `username` - User's username
- `email` - User's email
- `realm_roles` - List of the user's realm-level roles
- `client_roles(client)` - List of the user's roles on a specific client
- `token_data` - Raw token claims
- `has_realm_role(role)` - Check for a specific realm role
- `has_any_realm_role(roles)` - Check for any of the realm roles
- `has_client_role(client, role)` - Check for a specific client role
- `has_any_client_role(client, roles)` - Check for any of a client's roles

### Convenience Functions

These functions accept an AuthService instance and return configured dependencies:

- `get_token_data(auth_service)` - Create token validation dependency
- `get_current_user(auth_service)` - Create current user dependency
- `has_client_role(auth_service, client, role)` - Create client-role check dependency
- `has_any_client_role(auth_service, client, roles)` - Create multi-client-role check dependency
- `has_realm_role(auth_service, role)` - Create realm-role check dependency
- `has_any_realm_role(auth_service, roles)` - Create multi-realm-role check dependency

> **Service accounts:** `require_service_account`, `ServiceAccountTokenProvider`,
> and the related `AuthService`/`CurrentUser` members are documented in
> [docs/service-accounts.md](docs/service-accounts.md).
