from dataclasses import asdict
from typing import Any, Dict

from fastapi import HTTPException, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from jwt import PyJWKClient
import redis.asyncio as redis

from core.auth_service import DeltaAuthService
from core.delta_client import DeltaClient
from core.exceptions import DeltaError, AuthenticationError
from core.models import DeltaSettings
from core.ports.session_store import DeltaSessionStore
from core.session_service import DeltaSessionService
from core.token_validator import TokenValidator


class FastDelta:
    def __init__(
        self,
        settings: DeltaSettings,
        redis_client: redis.Redis,
        session_store: DeltaSessionStore,
    ):
        self._token_validator = TokenValidator(
            jwk_client=PyJWKClient(settings.jwks_endpoint, cache_keys=True, lifespan=3600),
            issuer=settings.issuer,
            audience=settings.audience if settings.audience is not None else settings.client_id,
        )
        self._session_service = DeltaSessionService(
            session_store=session_store,
            session_ttl_seconds=settings.session_ttl_seconds,
        )
        self._auth_service = DeltaAuthService(
            delta_client=DeltaClient(settings),
            redis_client=redis_client,
            token_validator=self._token_validator,
            session_service=self._session_service,
        )


    async def login(
        self,
        login_hint: str | None = None,
        app_state: Dict[str, Any] | None = None,
    ):
        data = await self._auth_service.login(
            login_hint=login_hint,
            app_state=app_state,
        )
        response = RedirectResponse(url=data.login_url)
        response.set_cookie(
            key="delta_login_sid",
            value=data.login_session_id,
            max_age=data.login_session_ttl,
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response


    async def callback(self, request: Request, response: Response):
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if code is None:
            raise HTTPException(400, "Missing authorization code")

        if state is None:
            raise HTTPException(400, "Missing state")
        
        login_session_id = request.cookies.get("delta_login_sid")
        if login_session_id is None:
            raise HTTPException(status_code=401, detail="Login session not found")
        
        try:
            callback_response = await self._auth_service.callback(
                code=code, state=state, login_session_id=login_session_id
            )
        except AuthenticationError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except DeltaError:
            raise HTTPException(status_code=500, detail="Internal server error")

        response.set_cookie(
            key="sid",
            value=callback_response.session_id,
            secure=True,
            httponly=True,
            samesite="lax",
        )

        return callback_response


    async def get_session(self, request: Request):
        session_id = request.cookies.get("sid")
        if not session_id:
            return None
            
        try:
            return await self._auth_service.get_session(session_id)
        except AuthenticationError:
            return None
        except DeltaError:
            raise HTTPException(status_code=500, detail="Internal server error")


    async def require_session(self, request: Request):
        session = await self.get_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="Valid session required")
        return session


    async def logout(self, request: Request, response: Response):
        session_id = request.cookies.get("sid")
        if session_id:
            await self._auth_service.logout(session_id)
        response.delete_cookie(
            key="sid",
            secure=True,
            httponly=True,
            samesite="lax",
        )
