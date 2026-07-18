import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request, Response, Depends

from adapters.fastapi_delta import FastDelta
from core.exceptions import AuthenticationError, DeltaError, SessionNotFoundError
from core.models import DeltaSession, DeltaUserInfo


def _make_session(**overrides) -> DeltaSession:
    defaults = dict(
        id="session-id",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        token_type="Bearer",
        scope="openid profile",
        user_info=DeltaUserInfo(sub="user-123", email="user@empresa.com"),
    )
    return DeltaSession(**{**defaults, **overrides})


def _make_fast_delta():
    with patch("adapters.fastapi_delta.PyJWKClient"), \
         patch("adapters.fastapi_delta.DeltaClient"), \
         patch("adapters.fastapi_delta.TokenValidator"), \
         patch("adapters.fastapi_delta.DeltaSessionService"), \
         patch("adapters.fastapi_delta.DeltaAuthService") as MockAuthService:

        from core.models import DeltaSettings

        settings = DeltaSettings(
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri="https://api.empresa.com/auth/callback",
            token_endpoint="https://idp.empresa.com/token",
            authorization_endpoint="https://idp.empresa.com/auth",
            jwks_endpoint="https://idp.empresa.com/certs",
            scopes="openid profile",
            session_ttl_seconds=3600,
            issuer="https://idp.empresa.com",
        )

        redis_mock = AsyncMock()
        store_mock = MagicMock()

        fast_delta = FastDelta(settings=settings, redis_client=redis_mock, session_store=store_mock)
        fast_delta._auth_service = AsyncMock()
        return fast_delta


class TestGetSession:
    @pytest.mark.asyncio
    async def test_returns_none_when_cookie_is_missing(self):
        fast_delta = _make_fast_delta()
        request = MagicMock()
        request.cookies = {}

        result = await fast_delta.get_session(request)

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_session_when_valid(self):
        fast_delta = _make_fast_delta()
        session = _make_session()
        fast_delta._auth_service.get_session = AsyncMock(return_value=session)

        request = MagicMock()
        request.cookies = {"sid": "session-id"}

        result = await fast_delta.get_session(request)

        assert result == session

    @pytest.mark.asyncio
    async def test_returns_none_on_authentication_error(self):
        fast_delta = _make_fast_delta()
        fast_delta._auth_service.get_session = AsyncMock(side_effect=SessionNotFoundError())

        request = MagicMock()
        request.cookies = {"sid": "session-inexistente"}

        result = await fast_delta.get_session(request)

        assert result is None

    @pytest.mark.asyncio
    async def test_raises_500_on_delta_error(self):
        fast_delta = _make_fast_delta()
        fast_delta._auth_service.get_session = AsyncMock(side_effect=DeltaError("erro interno"))

        request = MagicMock()
        request.cookies = {"sid": "session-id"}

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.get_session(request)

        assert exc_info.value.status_code == 500


class TestRequireSession:
    @pytest.mark.asyncio
    async def test_returns_session_when_valid(self):
        fast_delta = _make_fast_delta()
        session = _make_session()
        fast_delta._auth_service.get_session = AsyncMock(return_value=session)

        request = MagicMock()
        request.cookies = {"sid": "session-id"}

        result = await fast_delta.require_session(request)

        assert result == session

    @pytest.mark.asyncio
    async def test_raises_401_when_no_cookie(self):
        fast_delta = _make_fast_delta()

        request = MagicMock()
        request.cookies = {}

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.require_session(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_raises_401_when_session_not_found(self):
        fast_delta = _make_fast_delta()
        fast_delta._auth_service.get_session = AsyncMock(side_effect=SessionNotFoundError())

        request = MagicMock()
        request.cookies = {"sid": "session-invalida"}

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.require_session(request)

        assert exc_info.value.status_code == 401


class TestCallback:
    @pytest.mark.asyncio
    async def test_raises_400_when_code_is_missing(self):
        fast_delta = _make_fast_delta()

        request = MagicMock()
        request.query_params = MagicMock()
        request.query_params.get = MagicMock(return_value=None)
        request.cookies = {"delta_login_sid": "login-sid"}
        response = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.callback(request, response)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_raises_400_when_state_is_missing(self):
        fast_delta = _make_fast_delta()

        request = MagicMock()
        request.query_params.get = lambda key, default=None: "code-value" if key == "code" else None
        request.cookies = {"delta_login_sid": "login-sid"}
        response = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.callback(request, response)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_raises_401_when_login_session_cookie_is_missing(self):
        fast_delta = _make_fast_delta()

        request = MagicMock()
        request.query_params.get = lambda key, default=None: {"code": "code-value", "state": "state-value"}.get(key)
        request.cookies = {}
        response = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.callback(request, response)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_raises_401_on_authentication_error(self):
        fast_delta = _make_fast_delta()
        fast_delta._auth_service.callback = AsyncMock(side_effect=AuthenticationError("estado inválido"))

        request = MagicMock()
        request.query_params.get = lambda key, default=None: {"code": "code", "state": "state"}.get(key)
        request.cookies = {"delta_login_sid": "login-sid"}
        response = MagicMock()
        response.set_cookie = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_delta.callback(request, response)

        assert exc_info.value.status_code == 401


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_deletes_session_and_cookie(self):
        fast_delta = _make_fast_delta()
        fast_delta._auth_service.logout = AsyncMock()

        request = MagicMock()
        request.cookies = {"sid": "session-id"}
        response = MagicMock()
        response.delete_cookie = MagicMock()

        await fast_delta.logout(request, response)

        fast_delta._auth_service.logout.assert_called_once_with("session-id")
        response.delete_cookie.assert_called_once_with(
            key="sid",
            secure=True,
            httponly=True,
            samesite="lax",
        )

    @pytest.mark.asyncio
    async def test_logout_only_deletes_cookie_when_no_session(self):
        fast_delta = _make_fast_delta()
        fast_delta._auth_service.logout = AsyncMock()

        request = MagicMock()
        request.cookies = {}
        response = MagicMock()
        response.delete_cookie = MagicMock()

        await fast_delta.logout(request, response)

        fast_delta._auth_service.logout.assert_not_called()
        response.delete_cookie.assert_called_once()
