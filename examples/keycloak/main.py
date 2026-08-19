import os

import redis.asyncio as redis
from fastoidc import FastOIDC
from fastoidc.core.models import OIDCSession
from fastoidc.stores import RedisSessionStore
from fastapi import FastAPI, Depends, Request, Response

redis_client = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
session_store = RedisSessionStore(redis_client=redis_client)


auth = FastOIDC.from_discovery(
    discovery_endpoint=os.getenv("DISCOVERY_ENDPOINT"),
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET"),
    redirect_uri=os.getenv("REDIRECT_URI"),
    scopes=os.getenv("SCOPES"),
    redis_client=redis_client,
    session_store=session_store,
    post_logout_redirect_uri="http://localhost:8000/"
)

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello, World!"}

@app.get("/auth/login")
async def login(redirect_to: str = "/dashboard"):
    return await auth.login(app_state=redirect_to)

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    callback_result = await auth.callback(request, response)
    return {"state": callback_result.app_state}

@app.get("/auth/logout")
async def logout(request: Request):
    return await auth.logout(request)

# Keycloak supports back-channel logout
@app.post("/auth/backchannel_logout")
async def backchannel_logout(request: Request):
    return await auth.backchannel_logout(request)

@app.get("/auth/me")
async def me(session: OIDCSession = Depends(auth.require_session)):
    return {
        "name": session.user_info.get("name"),
        "email": session.user_info.get("email"),
    }
