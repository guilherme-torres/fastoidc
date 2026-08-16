from typing import Any, Dict

from fastapi import HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from jwt import PyJWKClient
import redis.asyncio as redis

from fastoidc.core.auth_service import OIDCAuthService
from fastoidc.core.oidc_client import OIDCClient
from fastoidc.exceptions import AuthenticationError, OIDCError, SessionNotFoundError
from fastoidc.core.models import OIDCSettings
from fastoidc.stores import OIDCSessionStore
from fastoidc.core.session_service import OIDCSessionService
from fastoidc.core.token_validator import TokenValidator


class FastOIDC:
    """FastAPI integration helper for managing FastOIDC OIDC authentication and sessions."""

    def __init__(
        self,
        settings: OIDCSettings,
        redis_client: redis.Redis,
        session_store: OIDCSessionStore,
    ):
        """Initializes FastOIDC with setting configurations, Redis, and custom session store."""
        self._token_validator = TokenValidator(
            jwk_client=PyJWKClient(settings.jwks_endpoint, cache_keys=True, lifespan=3600),
            issuer=settings.issuer,
            audience=settings.audience if settings.audience is not None else settings.client_id,
        )
        self._session_service = OIDCSessionService(
            session_store=session_store,
            session_ttl_seconds=settings.session_ttl_seconds,
        )
        self._auth_service = OIDCAuthService(
            oidc_client=OIDCClient(settings),
            redis_client=redis_client,
            token_validator=self._token_validator,
            session_service=self._session_service,
        )


    async def login(
        self,
        login_hint: str | None = None,
        app_state: Any = None,
    ):
        """Initiates the login flow, returning a redirect response and setting a temporary login cookie."""
        data = await self._auth_service.login(
            login_hint=login_hint,
            app_state=app_state,
        )
        response = RedirectResponse(url=data.login_url)
        response.set_cookie(
            key="fastoidc_login",
            value=data.login_session_id,
            max_age=data.login_session_ttl,
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response


    async def callback(self, request: Request, response: Response):
        """Handles the OIDC callback, validates state/session, sets session cookie, and returns callback response."""
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if code is None:
            raise HTTPException(400, "Missing authorization code")

        if state is None:
            raise HTTPException(400, "Missing state")
        
        login_session_id = request.cookies.get("fastoidc_login")
        if login_session_id is None:
            raise HTTPException(status_code=401, detail="Login session not found")
        
        try:
            callback_response = await self._auth_service.callback(
                code=code, state=state, login_session_id=login_session_id
            )
        except AuthenticationError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except OIDCError:
            raise HTTPException(status_code=500, detail="Internal server error")

        response.set_cookie(
            key="fastoidc_session",
            value=callback_response.session_id,
            secure=True,
            httponly=True,
            samesite="lax",
        )

        return callback_response


    async def get_session(self, request: Request):
        """Retrieves the active session from request cookies, verifying/refreshing it if needed."""
        session_id = request.cookies.get("fastoidc_session")
        if not session_id:
            return None
            
        try:
            return await self._auth_service.get_session(session_id)
        except AuthenticationError:
            return None
        except OIDCError:
            raise HTTPException(status_code=500, detail="Internal server error")


    async def require_session(self, request: Request):
        """FastAPI dependency that enforces a valid session, raising 401 if missing or invalid."""
        session = await self.get_session(request)
        if not session:
            raise HTTPException(status_code=401, detail="Valid session required")
        return session


    async def logout(self, request: Request) -> RedirectResponse:
        """Logs the user out by deleting session from storage, clearing cookies, and redirecting to the IdP."""
        session_id = request.cookies.get("fastoidc_session")
        logout_url = "/"
        
        if session_id:
            redirect_url = await self._auth_service.logout(session_id)
            if redirect_url:
                logout_url = redirect_url

        response = RedirectResponse(url=logout_url)
        response.delete_cookie(
            key="fastoidc_session",
            secure=True,
            httponly=True,
            samesite="lax",
        )
        return response

    async def backchannel_logout(self, request: Request) -> Response:
        """Handles Back-Channel Logout notification from the IdP."""
        form = await request.form()
        logout_token = form.get("logout_token")

        if not logout_token:
            # OAuth 2.0 error format
            return Response(
                content='{"error": "invalid_request", "error_description": "Missing logout_token"}',
                status_code=400,
                media_type="application/json",
                headers={"Cache-Control": "no-store"}
            )

        try:
            await self._auth_service.backchannel_logout(logout_token)
            return Response(status_code=200, headers={"Cache-Control": "no-store"})
        except OIDCError:
            return Response(
                content='{"error": "invalid_request", "error_description": "Invalid back-channel logout token"}',
                status_code=400,
                media_type="application/json",
                headers={"Cache-Control": "no-store"}
            )
