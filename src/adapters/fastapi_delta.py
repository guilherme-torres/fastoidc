from typing import Any, Dict

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse
import redis.asyncio as redis

from core.auth_service import DeltaAuthService
from core.delta_client import DeltaClient
from core.exceptions import DeltaError, AuthenticationError
from core.models import DeltaSettings


class FastDelta:
    def __init__(
        self,
        settings: DeltaSettings,
        redis_client: redis.Redis,
    ):
        self._auth_service = DeltaAuthService(
            delta_client=DeltaClient(settings),
            redis_client=redis_client,
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


    async def callback(self, request: Request):
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
        
        return callback_response
