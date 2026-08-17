import base64
import hashlib
import json
from datetime import datetime, timezone
from secrets import token_urlsafe, token_hex
from typing import Any

import jwt
import redis.asyncio as redis

from fastoidc.core.oidc_client import OIDCClient
from fastoidc.exceptions import LoginSessionExpiredError, InvalidStateError, SessionNotFoundError, BackchannelLogoutError
from fastoidc.core.models import OIDCCallbackResponse, OIDCLoginResponse
from fastoidc.core.session_service import OIDCSessionService
from fastoidc.core.token_validator import TokenValidator
from fastoidc.utils.hashing import hash_string


class PKCE():
    """Helper class for generating PKCE (Proof Key for Code Exchange) code verifiers and challenges."""
    def generate_code_verifier(self) -> str:
        """Generates a secure cryptographically random code verifier string."""
        return token_hex(64)
    
    def get_code_challenge(self, code_verifier: str) -> str:
        """Derives the SHA-256 code challenge from a given code verifier."""
        return base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")


class OIDCAuthService:
    """Service orchestration class handling OIDC login, callback, session fetching, and logout."""
    def __init__(
        self,
        oidc_client: OIDCClient,
        redis_client: redis.Redis,
        token_validator: TokenValidator,
        session_service: OIDCSessionService,
    ):
        """Initializes the authentication service with FastOIDC client, Redis, token validator, and session service."""
        self._oidc_client = oidc_client
        self._redis_client = redis_client
        self._token_validator = token_validator
        self._session_service = session_service
        self._login_session_ttl = 600

    
    async def login(
        self,
        login_hint: str | None = None,
        app_state: Any = None,
    ):
        """Initiates the login flow by generating login URLs, PKCE codes, and storing login session data in Redis."""
        login_session_id = token_urlsafe(64)
        csrf_token = token_urlsafe(64)

        pkce = PKCE()
        code_verifier = pkce.generate_code_verifier()
        code_challenge = pkce.get_code_challenge(code_verifier)

        login_url = self._oidc_client.get_login_url(
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

        return OIDCLoginResponse(
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
        """Handles OIDC callback parameters, validates state and PKCE, and constructs the user session."""
        session_key = hash_string(login_session_id)
        login_session_data_raw = await self._redis_client.get(session_key)
        
        if not login_session_data_raw:
            raise LoginSessionExpiredError("Login session not found or expired")
            
        login_session_data = json.loads(login_session_data_raw)
        
        if login_session_data.get("csrf_token") != state:
            raise InvalidStateError("Invalid state parameter")
            
        await self._redis_client.delete(session_key)
        
        tokens = await self._oidc_client.get_tokens(
            auth_code=code,
            code_verifier=login_session_data.get("code_verifier"),
        )

        user_info = self._token_validator.validate(tokens.id_token)

        id_token_claims = jwt.decode(tokens.id_token, options={"verify_signature": False})
        sid = id_token_claims.get("sid")

        session = await self._session_service.create(
            tokens=tokens,
            user_info=user_info,
            metadata=None,
            sid=sid,
        )
        
        return OIDCCallbackResponse(
            session_id=session.id,
            user_info=user_info,
            app_state=login_session_data.get("app_state"),
        )
    

    async def get_session(self, session_id: str):
        """Retrieves and returns the session, automatically refreshing tokens if the session has expired."""
        session = await self._session_service.get(session_id)
        if not session:
            raise SessionNotFoundError("Session not found")

        now = datetime.now(timezone.utc)
        if session.access_token_expires_at <= now:
            if not session.refresh_token:
                raise LoginSessionExpiredError("Session expired and no refresh token available")

            lock_key = f"fastoidc:lock:refresh_session:{session_id}"
            
            async with self._redis_client.lock(lock_key, timeout=10.0, blocking_timeout=5.0):
                session = await self._session_service.get(session_id)
                if session and session.access_token_expires_at > datetime.now(timezone.utc):
                    return session
                
                tokens = await self._oidc_client.refresh_tokens(session.refresh_token)
                
                user_info = session.user_info
                if tokens.id_token:
                    user_info = self._token_validator.validate(tokens.id_token)

                session = await self._session_service.update(
                    session_id=session.id,
                    tokens=tokens,
                    user_info=user_info
                )
                
        return session


    async def logout(self, session_id: str) -> str | None:
        """Logs the user out locally and returns the IdP logout URL if available."""
        session = await self._session_service.get(session_id)
        logout_url = None

        if session and session.id_token:
            try:
                logout_url = self._oidc_client.get_logout_url(id_token_hint=session.id_token)
            except Exception:
                pass  # Ignore errors if logout_endpoint is not configured

        await self._session_service.delete(session_id)
        return logout_url


    async def backchannel_logout(self, logout_token: str):
        """Processes a Back-Channel Logout Token from the IdP and destroys the associated session."""
        sid = self._token_validator.validate_logout_token(logout_token)
        sid_hash = hash_string(sid)
        await self._session_service.delete_by_sid(sid_hash)
