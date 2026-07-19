# FastOIDC

FastOIDC is a native OIDC/OAuth2 authentication library for FastAPI, focusing on security, high performance, and scalability. It implements the Authorization Code flow with PKCE and stores session states using Redis.

## Core Features

- OAuth2 / OpenID Connect Authentication (Authorization Code + PKCE)
- Distributed stateful session management with Redis
- Automatic Token Renewal (Refresh Tokens) protected against race conditions
- Native dependency injection for FastAPI (`Depends`)

## Installation

```bash
pip install fastoidc
```

## Configuration and Initialization

Create your application configuration and initialize the core library instance by linking your Redis connection.

```python
import redis.asyncio as redis
from fastapi import FastAPI
from fastoidc import FastOIDC, OIDCSettings, RedisSessionStore


settings = OIDCSettings(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="https://your-api.com/auth/callback",
    token_endpoint="https://idp.company.com/token",
    authorization_endpoint="https://idp.company.com/auth",
    jwks_endpoint="https://idp.company.com/certs",
    scopes="openid profile email",
    session_ttl_seconds=3600,
    issuer="https://idp.company.com",
    audience="your-client-id"
)

redis_client = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
session_store = RedisSessionStore(redis_client=redis_client)

fast_oidc = FastOIDC(
    settings=settings,
    redis_client=redis_client,
    session_store=session_store
)

app = FastAPI()
```

## Creating Authentication Routes

Expose the login, callback, and logout routes in your FastAPI application for the flow to work.

### Using App State

You can optionally pass a custom string (like a target URL to redirect back to after login) as `app_state` to the `login` method. FastOIDC securely stores this state in Redis during the PKCE flow and returns it back to you in the callback.

```python
from fastapi import Request, Response
from fastoidc.models import OIDCCallbackResponse

@app.get("/auth/login")
async def login(return_to: str = "/dashboard"):
    # Pass 'return_to' as app_state so it is preserved during the OAuth flow
    return await fast_oidc.login(app_state=return_to)


@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    callback_result: OIDCCallbackResponse = await fast_oidc.callback(request, response)
    
    # Retrieve the state preserved from the login request
    redirect_target = callback_result.app_state or "/"
    
    # Do something with the session (e.g., sync to local DB)
    print(f"User {callback_result.session.user_info.email} logged in!")
    
    # Redirect the user to their original destination
    return RedirectResponse(url=redirect_target)


@app.post("/auth/logout")
async def logout(request: Request, response: Response):
    await fast_oidc.logout(request, response)
    return {"status": "logged out"}
```

## Protecting Routes (Basic Usage)

The library exports native shortcuts to protect routes using dependency injection. The `fast_oidc.require_session` dependency ensures that only users with a valid session can access the route, returning `HTTP 401` otherwise.

```python
from fastapi import Depends
from fastoidc.models import OIDCSession

@app.get("/api/protected-resource")
async def fetch_resource(session: OIDCSession = Depends(fast_oidc.require_session)):
    return {
        "user_id": session.user_info.sub,
        "email": session.user_info.email,
        "token": session.access_token
    }
```

## Optional Session Usage

For routes where authentication is not mandatory but alters the system behavior if present (like showing a personalized profile vs a generic homepage), use the `get_session` method.

```python
@app.get("/api/showcase")
async def showcase(session: OIDCSession | None = Depends(fast_oidc.get_session)):
    if session:
        return {"data": "Personalized Showcase"}
    return {"data": "Generic Showcase"}
```