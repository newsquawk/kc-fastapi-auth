# Newsquawk Auth Package

Shared authentication package for Newsquawk services using JWT/JWKS token validation.

## Installation

Install this package directly from the public git repository, pinned to release `v0.1.1`.

Using pipenv:

```bash
pipenv install git+https://github.com/newsquawk/kc-fastapi-auth.git@v0.1.1#egg=newsquawk-auth
```

Or with pip:

```bash
pip install git+https://github.com/newsquawk/kc-fastapi-auth.git@v0.1.1
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

## Stub Mode (fake Keycloak, no server)

For local development and tests you can run without a real Keycloak/JWKS
endpoint. In **stub mode** the library ships a tiny fake identity provider:
users, bcrypt password hashes and role assignments come from a YAML file, and
logging in mints a **real HS256-signed JWT**. That token is then validated by
`AuthService(stub_mode=True)` exactly as a production token would be — same
routes, same dependencies, same role checks. Only the trust root differs (a
shared symmetric secret instead of Keycloak's JWKS), so unlike a "skip
verification" shim, signatures and expiry **are** verified.

The stub helpers are optional. Install them with the `stub` extra:

```bash
pip install "newsquawk-auth[stub]"     # adds bcrypt + PyYAML
```

### Wire it up

```python
from newsquawk_auth import AuthService, AuthDependencies
from newsquawk_auth.stub import StubIdentityProvider, build_stub_login_router

# 1. The validator — same object your routes already use.
auth_service = AuthService(stub_mode=True)      # verifies HS256 with the shared secret
auth_deps = AuthDependencies(auth_service)

# 2. The issuer — a fake Keycloak reading users from YAML.
provider = StubIdentityProvider()               # data_path=None -> bundled sample users

# 3. Expose a login endpoint (opt-in — the library never mounts routes for you).
app.include_router(build_stub_login_router(provider))   # POST /dev/login
```

Log in to get a token, then call protected routes with it as a normal bearer
token:

```bash
TOKEN=$(curl -s http://localhost:8000/dev/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"desk@newsquawk.com","password":"..."}' | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/notifications
```

### The data file

`StubIdentityProvider(data_path="stub_users.yaml")` reads a YAML file of this
shape (a bundled **sample** is used when `data_path` is omitted):

```yaml
users:
- user: desk@newsquawk.com                       # username; an "@" also becomes the email
  id: c49a421f-abb3-4d38-af7c-79b6c423bab2        # becomes the token "sub"
  password_hash: $2b$12$8LIObJM4UTGSgpmHh3fsoO...  # bcrypt hash (plaintext not supported)
roles:                                            # role -> user ids holding it
  view:  [c49a421f-abb3-4d38-af7c-79b6c423bab2]
  admin: [c49a421f-abb3-4d38-af7c-79b6c423bab2]   # -> realm_access.roles on the token
```

Roles map to **realm roles** (`realm_access.roles`), so `has_realm_role(...)`
works unchanged. Generate a bcrypt hash with:

```python
import bcrypt
print(bcrypt.hashpw(b"your-password", bcrypt.gensalt(rounds=12)).decode())
```

### The shared secret

Issuer and validator must sign/verify with the same HS256 secret. Both default
to `newsquawk_auth.DEFAULT_STUB_SECRET` so zero-config works out of the box;
override it in both places for anything beyond a laptop:

```python
provider     = StubIdentityProvider(secret=SETTINGS.stub_secret)
auth_service = AuthService(stub_mode=True, stub_secret=SETTINGS.stub_secret)
```

The stub path only ever uses HS256 and the production path only ever uses
RS256/JWKS, so a stub token can never be accepted by a real validator (and vice
versa).

### Tests

`provider.issue_token(username_or_id)` mints a token without a password, handy
in test fixtures:

```python
token = provider.issue_token("desk@newsquawk.com")
client.get("/notifications", headers={"Authorization": f"Bearer {token}"})
```

> ⚠️ **Never enable `stub_mode` in production.** Gate it behind an environment
> flag in the consuming service, e.g. `stub_mode=settings.auth_stub_mode`.
> `dev_mode=True` still works as a deprecated alias for `stub_mode=True`, but
> the old `dev_users` dict lookup has been removed in favour of this flow.

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

### Non-blocking JWKS fetch

`verify_and_decode_token` is fully `async` and never blocks the event loop.
The JWKS is fetched with `httpx.AsyncClient` (`await`ed, not run synchronously),
so while one request is waiting on the JWKS endpoint, other concurrent requests
on the same worker keep progressing.

The fetched key set is cached per `AuthService` for `jwks_cache_lifespan`
seconds (default `300`). A cache miss (cold cache, expiry, or a rotated `kid`)
triggers a single refresh guarded by an `asyncio.Lock`: when many requests miss
at once, exactly **one** fetch runs (single-flight) and the rest reuse its
result — no thundering herd against Keycloak. A failed refresh (network error,
non-2xx, or unusable JSON) leaves any previously good cache intact rather than
clearing it.

When the JWKS endpoint is unreachable and there is no usable cache to fall back
on, validation raises **HTTP 503** ("Authentication service temporarily
unavailable") rather than 401 — the caller's token isn't invalid, the identity
provider is down. A bad or expired token, or one referencing an unknown signing
key, still returns **401**. The underlying `JWKSUnavailableError` is exported
from `newsquawk_auth` if you want to catch it directly.

```python
auth_service = AuthService(
    jwks_url=settings.keycloak_jwks_url,
    audience="my-api",
    jwks_cache_lifespan=300,  # seconds to cache keys before refreshing
    jwks_timeout=5,           # seconds for the JWKS HTTP fetch (applied to all phases)
)
```

`jwks_timeout` defaults to a tight `httpx.Timeout(5.0, connect=2.0)` (connect
2 s, read 5 s). Because the fetch runs inside the single-flight lock, a slow
endpoint would otherwise stall every concurrent cache-miss validation until it
times out, so the default is deliberately short. Pass a plain number to set all
phases at once, or an `httpx.Timeout` for finer control:

```python
import httpx

auth_service = AuthService(
    jwks_url=settings.keycloak_jwks_url,
    audience="my-api",
    jwks_timeout=httpx.Timeout(5.0, connect=2.0, read=5.0),
)
```

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
