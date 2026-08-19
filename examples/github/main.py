import os

import redis.asyncio as redis
from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from fastoidc import FastOIDC
from fastoidc.stores import RedisSessionStore
from fastoidc.core.models import OIDCSession


redis_client = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
session_store = RedisSessionStore(redis_client=redis_client)

auth = FastOIDC.from_config(
    client_id=os.environ.get("GITHUB_CLIENT_ID", "YOUR_GITHUB_CLIENT_ID"),
    client_secret=os.environ.get("GITHUB_CLIENT_SECRET", "YOUR_GITHUB_CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/auth/callback",
    scopes="read:user user:email",
    authorization_endpoint="https://github.com/login/oauth/authorize",
    token_endpoint="https://github.com/login/oauth/access_token",
    userinfo_endpoint="https://api.github.com/user",
    redis_client=redis_client,
    session_store=session_store,
)

app = FastAPI()


@app.get("/")
async def index(session: OIDCSession | None = Depends(auth.get_session)):
    if session:
        return HTMLResponse(
            f"<h1>Welcome, {session.user_info.get('login')}!</h1>"
            f"<img src='{session.user_info.get('avatar_url')}' width='100'><br>"
            f"<a href='/auth/logout'>Logout</a>"
        )
    return HTMLResponse(
        "<h1>Welcome!</h1>"
        "<a href='/auth/login'>Login with GitHub</a>"
    )


@app.get("/auth/login")
async def login():
    return await auth.login()


@app.get("/auth/callback")
async def callback(request: Request):
    response = RedirectResponse(status_code=302, url="/")
    await auth.callback(request, response)
    return response


@app.get("/auth/logout")
async def logout(request: Request):
    return await auth.logout(request)
