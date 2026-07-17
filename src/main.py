import base64
import hashlib
import json
from secrets import token_urlsafe, token_hex
from typing import Any, Dict
from urllib.parse import urlencode

import httpx
import redis.asyncio as redis
from pydantic import BaseModel
from fastapi.responses import RedirectResponse

from utils.hashing import hash_string


class DeltaError(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class DeltaSettings(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: str
    token_endpoint: str
    authorization_endpoint: str
    jwks_endpoint: str
    scopes: str


class DeltaTokensResponse(BaseModel):
    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str | None = None


class DeltaClient:
    def __init__(self, settings: DeltaSettings):
        self._settings = settings
        self._auth = httpx.BasicAuth(
            username=self._settings.client_id,
            password=self._settings.client_secret,
        )


    def get_login_url(
        self,
        login_hint: str | None = None,
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str = "S256",
    ) -> str:
        url_params = {
            "response_type": "code",
            "client_id": self._settings.client_id,
            "scope": self._settings.scopes,
            "redirect_uri": self._settings.redirect_uri,
        }
        if login_hint:
            url_params["login_hint"] = login_hint
        if state:
            url_params["state"] = state
        if code_challenge:
            url_params["code_challenge"] = code_challenge
            url_params["code_challenge_method"] = code_challenge_method
        return f"{self._settings.authorization_endpoint}?{urlencode(url_params)}"
    

    async def get_tokens(
        self,
        auth_code: str,
        code_verifier: str | None = None,
    ):
        payload = {
            "code": auth_code,
            "grant_type": "authorization_code",
            "redirect_uri": self._settings.redirect_uri,
            "client_id": self._settings.client_id,
            "client_secret": self._settings.client_secret,
        }
        if code_verifier:
            payload["code_verifier"] = code_verifier
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=self._settings.token_endpoint,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=payload,
                )
                data = response.json()
                print(data)
                response.raise_for_status()
                return DeltaTokensResponse(
                    access_token=data.get("access_token"),
                    refresh_token=data.get("refresh_token"),
                    scope=data.get("scope"),
                    id_token=data.get("id_token"),
                    token_type=data.get("token_type"),
                    expires_in=data.get("expires_in"),
                )
        except httpx.HTTPStatusError as e:
            print(e)
            raise DeltaError(message=f"{e}")


class DeltaAuthService:
    def __init__(
        self,
        delta_client: DeltaClient,
        redis_client: redis.Redis,
    ):
        self._delta_client = delta_client
        self._redis_client = redis_client
        self._login_session_ttl = 600

    
    async def login(
        self,
        login_hint: str | None = None,
        state: Dict[str, Any] | None = None,
    ):
        login_session_id = token_urlsafe(64)
        csrf_token = token_urlsafe(64)
        code_verifier = token_hex(64)
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")
        login_url = self._delta_client.get_login_url(
            login_hint=login_hint,
            state=csrf_token,
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )
        login_session_data = {
            "csrf_token": csrf_token,
            "code_verifier": code_verifier,
            "state": state
        }
        await self._redis_client.set(
            hash_string(login_session_id),
            json.dumps(login_session_data),
            ex=self._login_session_ttl,
        )
        response = RedirectResponse(url=login_url)
        response.set_cookie(
            key="delta_login_sid",
            value=login_session_id,
            max_age=self._login_session_ttl,
            httponly=True,
            samesite="lax",
            secure=True,
        )
        return response
    

    async def callback(self, code: str, state: str, login_session_id: str):
        session_key = hash_string(login_session_id)
        session_data_raw = await self._redis_client.get(session_key)
        
        if not session_data_raw:
            raise DeltaError("Login session not found or expired")
            
        session_data = json.loads(session_data_raw)
        
        if session_data.get("csrf_token") != state:
            raise DeltaError("Invalid state parameter")
            
        await self._redis_client.delete(session_key)
        
        tokens = await self._delta_client.get_tokens(
            auth_code=code,
            code_verifier=session_data.get("code_verifier"),
        )
        
        return {
            "tokens": tokens,
            "state": session_data.get("state"),
        }
