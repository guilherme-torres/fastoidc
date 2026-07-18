from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import Depends, FastAPI, Request, Response

from adapters.fastapi_delta import FastDelta
from adapters.redis_session_store import RedisSessionStore
from core.models import DeltaSession, DeltaSettings


redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

delta_settings = DeltaSettings(
    client_id="",
    client_secret="",
    redirect_uri="http://localhost:8000/auth/callback",
    token_endpoint="",
    authorization_endpoint="",
    jwks_endpoint="",
    scopes="openid",
    issuer="",
    session_ttl_seconds=600,
)

session_store = RedisSessionStore(redis_client=redis_client)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await redis_client.aclose()

app = FastAPI(lifespan=lifespan)

fast_delta = FastDelta(
    settings=delta_settings,
    redis_client=redis_client,
    session_store=session_store,
)

@app.get("/auth/login")
async def login(
    login_hint: str | None = None,
    name: str | None = None,
):
    return await fast_delta.login(
        login_hint=login_hint,
        app_state={"name": name},
    )

@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    callback_response = await fast_delta.callback(request, response)
    return {"state": callback_response.app_state}

@app.get("/auth/me")
async def me(session: DeltaSession = Depends(fast_delta.get_session)):
    user_info = session.user_info
    return {
        "name": user_info.name,
        "email": user_info.email,
    }
