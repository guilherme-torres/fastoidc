from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, Request

from adapters.fastapi_delta import FastDelta
from core.models import DeltaSettings


redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

delta_settings = DeltaSettings(
    client_id="CLIENT_ID",
    client_secret="CLIENT_SECRET",
    redirect_uri="http://localhost:8000/auth/callback",
    token_endpoint="TOKEN_ENDPOINT",
    authorization_endpoint="AUTHORIZE_ENDPOINT",
    jwks_endpoint="JWKS_ENDPOINT",
    scopes="openid"
)

fast_delta = FastDelta(
    settings=delta_settings,
    redis_client=redis_client
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await redis_client.aclose()

app = FastAPI(lifespan=lifespan)

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
async def callback(request: Request):
    callback_response = await fast_delta.callback(request)
    return {"state": callback_response.app_state}
