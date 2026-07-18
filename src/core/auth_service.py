import base64
import hashlib
import json
from datetime import datetime, timezone
from secrets import token_urlsafe, token_hex
from typing import Any, Dict

import redis.asyncio as redis

from core.delta_client import DeltaClient
from core.exceptions import LoginSessionExpiredError, InvalidStateError, SessionNotFoundError
from core.models import DeltaCallbackResponse, DeltaLoginResponse
from core.session_service import DeltaSessionService
from core.token_validator import TokenValidator
from utils.hashing import hash_string


class PKCE():
    def generate_code_verifier(self) -> str:
        return token_hex(64)
    
    def get_code_challenge(self, code_verifier: str) -> str:
        return base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")


class DeltaAuthService:
    def __init__(
        self,
        delta_client: DeltaClient,
        redis_client: redis.Redis,
        token_validator: TokenValidator,
        session_service: DeltaSessionService,
    ):
        self._delta_client = delta_client
        self._redis_client = redis_client
        self._token_validator = token_validator
        self._session_service = session_service
        self._login_session_ttl = 600

    
    async def login(
        self,
        login_hint: str | None = None,
        app_state: Dict[str, Any] | None = None,
    ):
        login_session_id = token_urlsafe(64)
        csrf_token = token_urlsafe(64)

        pkce = PKCE()
        code_verifier = pkce.generate_code_verifier()
        code_challenge = pkce.get_code_challenge(code_verifier)

        login_url = self._delta_client.get_login_url(
            login_hint=login_hint,
            state=csrf_token,
            code_challenge=code_challenge,
        )

        login_session_data = {
            "csrf_token": csrf_token,
            "code_verifier": code_verifier,
            "app_state": app_state,
        }

        await self._redis_client.set(
            hash_string(login_session_id),
            json.dumps(login_session_data),
            ex=self._login_session_ttl,
        )

        return DeltaLoginResponse(
            login_url=login_url,
            login_session_id=login_session_id,
            login_session_ttl=self._login_session_ttl,
        )
    

    async def callback(
        self,
        code: str,
        state: str,
        login_session_id: str
    ):
        session_key = hash_string(login_session_id)
        login_session_data_raw = await self._redis_client.get(session_key)
        
        if not login_session_data_raw:
            raise LoginSessionExpiredError("Login session not found or expired")
            
        login_session_data = json.loads(login_session_data_raw)
        
        if login_session_data.get("csrf_token") != state:
            raise InvalidStateError("Invalid state parameter")
            
        await self._redis_client.delete(session_key)
        
        tokens = await self._delta_client.get_tokens(
            auth_code=code,
            code_verifier=login_session_data.get("code_verifier"),
        )

        user_info = self._token_validator.validate(tokens.id_token)

        session = await self._session_service.create(
            tokens=tokens,
            user_info=user_info,
            metadata=None,
        )
        
        return DeltaCallbackResponse(
            session_id=session.id,
            user_info=user_info,
            app_state=login_session_data.get("app_state"),
        )
    

    async def get_session(self, session_id: str):
        session = await self._session_service.get(session_id)
        if not session:
            raise SessionNotFoundError("Session not found")

        now = datetime.now(timezone.utc)
        if session.access_token_expires_at <= now:
            if not session.refresh_token:
                raise LoginSessionExpiredError("Session expired and no refresh token available")

            lock_key = f"lock:refresh_session:{session_id}"
            
            async with self._redis_client.lock(lock_key, timeout=10.0, blocking_timeout=5.0):
                session = await self._session_service.get(session_id)
                if session and session.access_token_expires_at > datetime.now(timezone.utc):
                    return session
                
                tokens = await self._delta_client.refresh_tokens(session.refresh_token)
                
                user_info = session.user_info
                if tokens.id_token:
                    user_info = self._token_validator.validate(tokens.id_token)

                session = await self._session_service.update(
                    session_id=session.id,
                    tokens=tokens,
                    user_info=user_info
                )
                
        return session

    async def logout(self, session_id: str):
        await self._session_service.delete(session_id)
