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
from fastapi import FastAPI
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
    audience="token-audience"
)

redis_client = redis.Redis.from_url(
    "redis://localhost:6379/0", decode_responses=True
)

session_store = RedisSessionStore(redis_client=redis_client)

auth = FastOIDC(
    settings=oidc_settings,
    redis_client=redis_client,
    session_store=session_store
)

app = FastAPI()

@app.get("/auth/login")
async def login(redirect_to: str = "/dashboard"):
    # You can pass an optional state
    return await auth.login(app_state=redirect_to)

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    callback_result = await auth.callback(request, response)
    # Retrieving state
    app_state = callback_result.app_state
    # Do something
    return {"state": callback_result.app_state}

@app.get("/auth/logout")
async def logout(request: Request, response: Response):
    await auth.logout(request, response)
    return {"status": "logged out"}

# Authenticate your routes
@app.get("/auth/me")
async def me(session: OIDCSession = Depends(auth.require_session)):
    return {
        "name": session.user_info.name,
        "email": session.user_info.email,
        "picture": session.user_info.picture,
    }
```

## Optional Session Usage

For endpoints where authentication is optional but changes the response when the user is logged in, use the `get_session` dependency.

```python
@app.get("/welcome")
async def welcome(session: OIDCSession | None = Depends(auth.get_session)):
    if session:
        return {"message": f"Welcome back, {session.user_info.name}"}
    return {"message" "Welcome, stranger"}
```

## Using Session Metadata

The `OIDCSession` object includes a `metadata` dictionary field that you can use to attach custom data (like tenant IDs, custom roles, or permissions) to an active session.

Since you instantiate the `session_store` directly in your application, you can persist any changes made to a session by calling the store's update method.

```python
@app.post("/auth/roles")
async def update_roles(session: OIDCSession = Depends(auth.require_session)):
    # Initialize metadata if not present
    if not session.metadata:
        session.metadata = {}
    
    # Store custom business logic data
    session.metadata["roles"] = ["admin", "editor"]
    
    # Persist the changes back to Redis (or your custom store)
    await session_store.update(session)
    
    return {"status": "roles updated"}
```

## Custom Authentication Dependencies

You can leverage FastAPI's powerful `Depends` system to create custom authorization dependencies on top of the base `auth.require_session`. 

For example, if you stored a list of roles in the session's `metadata`, you can easily create a `require_admin` dependency that blocks unauthorized users:

```python
from fastapi import HTTPException

async def require_admin(session: OIDCSession = Depends(auth.require_session)):
    # Safely retrieve roles from metadata
    roles = session.metadata.get("roles", []) if session.metadata else []
    
    if "admin" not in roles:
        raise HTTPException(
            status_code=403, 
            detail="Admin required"
        )
    
    return session

# Protect your route using the custom dependency
@app.get("/admin/dashboard")
async def admin_dashboard(session: OIDCSession = Depends(require_admin)):
    return {"message": f"Welcome to the admin area, {session.user_info.name}!"}
```
