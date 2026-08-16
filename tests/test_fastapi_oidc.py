import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request, Response, Depends

from fastoidc.integration import FastOIDC
from fastoidc.exceptions import AuthenticationError, OIDCError, SessionNotFoundError
from fastoidc.core.models import OIDCSession, OIDCUserInfo


def _make_session(**overrides) -> OIDCSession:
    defaults = dict(
        id="session-id",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        token_type="Bearer",
        scope="openid profile",
        user_info=OIDCUserInfo(sub="user-123", email="user@empresa.com"),
    )
    return OIDCSession(**{**defaults, **overrides})


def _make_fast_oidc():
    with patch("fastoidc.integration.PyJWKClient"), \
         patch("fastoidc.integration.OIDCClient"), \
         patch("fastoidc.integration.TokenValidator"), \
         patch("fastoidc.integration.OIDCSessionService"), \
         patch("fastoidc.integration.OIDCAuthService") as MockAuthService:

        from fastoidc.core.models import OIDCSettings

        settings = OIDCSettings(
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

        fast_oidc = FastOIDC(settings=settings, redis_client=redis_mock, session_store=store_mock)
        fast_oidc._auth_service = AsyncMock()
        return fast_oidc


class TestGetSession:
    @pytest.mark.asyncio
    async def test_returns_none_when_cookie_is_missing(self):
        fast_oidc = _make_fast_oidc()
        request = MagicMock()
        request.cookies = {}

        result = await fast_oidc.get_session(request)

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_session_when_valid(self):
        fast_oidc = _make_fast_oidc()
        session = _make_session()
        fast_oidc._auth_service.get_session = AsyncMock(return_value=session)

        request = MagicMock()
        request.cookies = {"fastoidc_session": "session-id"}

        result = await fast_oidc.get_session(request)

        assert result == session

    @pytest.mark.asyncio
    async def test_returns_none_on_authentication_error(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.get_session = AsyncMock(side_effect=SessionNotFoundError())

        request = MagicMock()
        request.cookies = {"fastoidc_session": "session-inexistente"}

        result = await fast_oidc.get_session(request)

        assert result is None

    @pytest.mark.asyncio
    async def test_raises_500_on_delta_error(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.get_session = AsyncMock(side_effect=OIDCError("erro interno"))

        request = MagicMock()
        request.cookies = {"fastoidc_session": "session-id"}

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.get_session(request)

        assert exc_info.value.status_code == 500


class TestRequireSession:
    @pytest.mark.asyncio
    async def test_returns_session_when_valid(self):
        fast_oidc = _make_fast_oidc()
        session = _make_session()
        fast_oidc._auth_service.get_session = AsyncMock(return_value=session)

        request = MagicMock()
        request.cookies = {"fastoidc_session": "session-id"}

        result = await fast_oidc.require_session(request)

        assert result == session

    @pytest.mark.asyncio
    async def test_raises_401_when_no_cookie(self):
        fast_oidc = _make_fast_oidc()

        request = MagicMock()
        request.cookies = {}

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.require_session(request)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_raises_401_when_session_not_found(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.get_session = AsyncMock(side_effect=SessionNotFoundError())

        request = MagicMock()
        request.cookies = {"fastoidc_session": "session-invalida"}

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.require_session(request)

        assert exc_info.value.status_code == 401


class TestCallback:
    @pytest.mark.asyncio
    async def test_raises_400_when_code_is_missing(self):
        fast_oidc = _make_fast_oidc()

        request = MagicMock()
        request.query_params = MagicMock()
        request.query_params.get = MagicMock(return_value=None)
        request.cookies = {"fastoidc_login": "login-sid"}
        response = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.callback(request, response)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_raises_400_when_state_is_missing(self):
        fast_oidc = _make_fast_oidc()

        request = MagicMock()
        request.query_params.get = lambda key, default=None: "code-value" if key == "code" else None
        request.cookies = {"fastoidc_login": "login-sid"}
        response = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.callback(request, response)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_raises_401_when_login_session_cookie_is_missing(self):
        fast_oidc = _make_fast_oidc()

        request = MagicMock()
        request.query_params.get = lambda key, default=None: {"code": "code-value", "state": "state-value"}.get(key)
        request.cookies = {}
        response = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.callback(request, response)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_raises_401_on_authentication_error(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.callback = AsyncMock(side_effect=AuthenticationError("estado inválido"))

        request = MagicMock()
        request.query_params.get = lambda key, default=None: {"code": "code", "state": "state"}.get(key)
        request.cookies = {"fastoidc_login": "login-sid"}
        response = MagicMock()
        response.set_cookie = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.callback(request, response)

        assert exc_info.value.status_code == 401


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_redirects_and_deletes_session_and_cookie(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.logout = AsyncMock(return_value="https://idp/logout")

        request = MagicMock()
        request.cookies = {"fastoidc_session": "session-id"}

        response = await fast_oidc.logout(request)

        fast_oidc._auth_service.logout.assert_called_once_with("session-id")
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "https://idp/logout"

    @pytest.mark.asyncio
    async def test_logout_redirects_to_root_when_no_session(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.logout = AsyncMock()

        request = MagicMock()
        request.cookies = {}

        response = await fast_oidc.logout(request)

        fast_oidc._auth_service.logout.assert_not_called()
        assert response.status_code in (302, 303, 307)
        assert response.headers["location"] == "/"


class TestBackchannelLogout:
    @pytest.mark.asyncio
    async def test_backchannel_logout_processes_valid_token(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.backchannel_logout = AsyncMock()

        form_mock = MagicMock()
        form_mock.get = MagicMock(return_value="valid-logout-token")
        request = MagicMock()
        request.form = AsyncMock(return_value=form_mock)

        await fast_oidc.backchannel_logout(request)

        fast_oidc._auth_service.backchannel_logout.assert_called_once_with("valid-logout-token")

    @pytest.mark.asyncio
    async def test_backchannel_logout_raises_400_when_token_missing(self):
        fast_oidc = _make_fast_oidc()

        form_mock = MagicMock()
        form_mock.get = MagicMock(return_value=None)
        request = MagicMock()
        request.form = AsyncMock(return_value=form_mock)

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.backchannel_logout(request)

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_backchannel_logout_raises_400_on_oidc_error(self):
        fast_oidc = _make_fast_oidc()
        fast_oidc._auth_service.backchannel_logout = AsyncMock(
            side_effect=OIDCError("erro interno")
        )

        form_mock = MagicMock()
        form_mock.get = MagicMock(return_value="valid-logout-token")
        request = MagicMock()
        request.form = AsyncMock(return_value=form_mock)

        with pytest.raises(HTTPException) as exc_info:
            await fast_oidc.backchannel_logout(request)

        assert exc_info.value.status_code == 400
