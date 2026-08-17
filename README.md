# FastOIDC

FastOIDC is a native OIDC/OAuth2 authentication library for FastAPI, focusing on security, high performance, and scalability. It implements the Authorization Code flow with PKCE and stores session states using Redis.

## Core Features

- OAuth2 / OpenID Connect Authentication (Authorization Code + PKCE)
- Distributed stateful session management with Redis
- Automatic Token Renewal
- Native dependency injection for FastAPI (`Depends`)

## Installation

```bash
pip install fastoidc
```

## Basic Usage

Create your application configuration and initialize the core library instance by linking your Redis connection.

```python
import redis.asyncio as redis
from fastapi import FastAPI, Depends, Request, Response
from fastoidc import FastOIDC, OIDCSettings
from fastoidc.stores import RedisSessionStore


oidc_settings = OIDCSettings(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="https://your-api.com/auth/callback",
    token_endpoint="https://idp.company.com/oauth2/token",
    authorization_endpoint="https://idp.company.com/oauth2/authorize",
    jwks_endpoint="https://idp.company.com/oauth2/jwks",
    scopes="openid profile email",
    session_ttl_seconds=86400,
    issuer="token-issuer",
    audience="token-audience",
    logout_endpoint="https://idp.company.com/oauth2/logout",  # Optional
    post_logout_redirect_uri="https://your-api.com/",         # Optional
)

redis_client = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
session_store = RedisSessionStore(redis_client=redis_client)

auth = FastOIDC(
    settings=oidc_settings,
    redis_client=redis_client,
    session_store=session_store,
)

app = FastAPI()

@app.get("/auth/login")
async def login(redirect_to: str = "/dashboard"):
    # You can pass an optional app state
    return await auth.login(app_state=redirect_to)

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    callback_result = await auth.callback(request, response)
    return {"state": callback_result.app_state}

@app.get("/auth/logout")
async def logout(request: Request):
    # Logs the user out locally and redirects them to the IdP to log out there
    return await auth.logout(request)

@app.post("/auth/backchannel_logout")
async def backchannel_logout(request: Request):
    # Receives the background logout notification from the IdP
    return await auth.backchannel_logout(request)

@app.get("/auth/me")
async def me(session = Depends(auth.require_session)):
    # user_info is a dict with all claims extracted from the ID token
    return {
        "name": session.user_info.get("name"),
        "email": session.user_info.get("email"),
        "picture": session.user_info.get("picture"),
    }
```

## Optional Session Usage

For endpoints where authentication is optional, use `get_session`. The route remains accessible to unauthenticated users:

```python
from fastoidc.core.models import OIDCSession

@app.get("/welcome")
async def welcome(session: OIDCSession | None = Depends(auth.get_session)):
    if session:
        return {"message": f"Welcome back, {session.user_info.get('name')}"}
    return {"message": "Welcome, stranger"}
```

## Using Session Metadata

The `OIDCSession` object includes a `metadata` dictionary field that you can use to attach custom data (like tenant IDs, roles, or permissions) to an active session.

Since you instantiate the `session_store` directly in your application, you can persist any changes by calling the store's update method:

```python
@app.post("/auth/roles")
async def update_roles(session = Depends(auth.require_session)):
    if not session.metadata:
        session.metadata = {}

    session.metadata["roles"] = ["admin", "editor"]

    await session_store.update(session)

    return {"status": "roles updated"}
```

## Custom Authentication Dependencies

You can leverage FastAPI's `Depends` system to build custom authorization layers on top of `auth.require_session`.

For example, to protect routes with a role check:

```python
from fastapi import HTTPException

async def require_admin(session = Depends(auth.require_session)):
    roles = session.metadata.get("roles", []) if session.metadata else []

    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="Admin required")

    return session

@app.get("/admin/dashboard")
async def admin_dashboard(session = Depends(require_admin)):
    return {"message": f"Welcome to the admin area, {session.user_info.get('name')}!"}
```
