import json
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from core.auth_service import DeltaAuthService
from core.exceptions import (
    InvalidStateError,
    LoginSessionExpiredError,
    SessionNotFoundError,
)
from core.models import (
    DeltaCallbackResponse,
    DeltaLoginResponse,
    DeltaSession,
    DeltaTokensResponse,
    DeltaUserInfo,
)
from utils.hashing import hash_string


def _make_tokens(**overrides) -> DeltaTokensResponse:
    defaults = dict(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        token_type="Bearer",
        expires_in=3600,
        scope="openid profile",
    )
    return DeltaTokensResponse(**{**defaults, **overrides})


def _make_session(**overrides) -> DeltaSession:
    defaults = dict(
        id="session-id",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        token_type="Bearer",
        scope="openid profile",
        user_info=DeltaUserInfo(sub="user-123"),
    )
    return DeltaSession(**{**defaults, **overrides})


def _make_user_info(**overrides) -> DeltaUserInfo:
    defaults = dict(sub="user-123", email="user@empresa.com")
    return DeltaUserInfo(**{**defaults, **overrides})


def _make_service(**overrides):
    delta_client = MagicMock()
    redis_client = AsyncMock()
    token_validator = MagicMock()
    session_service = AsyncMock()

    redis_client.lock = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=None), __aexit__=AsyncMock(return_value=False)))

    defaults = dict(
        delta_client=delta_client,
        redis_client=redis_client,
        token_validator=token_validator,
        session_service=session_service,
    )
    kwargs = {**defaults, **overrides}
    service = DeltaAuthService(**kwargs)
    return service, kwargs


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_returns_login_response(self):
        service, deps = _make_service()
        deps["delta_client"].get_login_url.return_value = "https://idp.empresa.com/auth?..."
        deps["redis_client"].set = AsyncMock()

        result = await service.login()

        assert isinstance(result, DeltaLoginResponse)
        assert result.login_url == "https://idp.empresa.com/auth?..."
        assert result.login_session_id is not None
        assert result.login_session_ttl == 600

    @pytest.mark.asyncio
    async def test_login_saves_session_to_redis(self):
        service, deps = _make_service()
        deps["delta_client"].get_login_url.return_value = "https://idp.empresa.com/auth"
        deps["redis_client"].set = AsyncMock()

        await service.login()

        deps["redis_client"].set.assert_called_once()
        call_args = deps["redis_client"].set.call_args
        saved_data = json.loads(call_args.args[1])
        assert "csrf_token" in saved_data
        assert "code_verifier" in saved_data

    @pytest.mark.asyncio
    async def test_login_with_app_state_saves_it_to_redis(self):
        service, deps = _make_service()
        deps["delta_client"].get_login_url.return_value = "https://idp.empresa.com/auth"
        deps["redis_client"].set = AsyncMock()

        await service.login(app_state={"redirect_to": "/dashboard"})

        call_args = deps["redis_client"].set.call_args
        saved_data = json.loads(call_args.args[1])
        assert saved_data["app_state"] == {"redirect_to": "/dashboard"}


class TestCallback:
    @pytest.mark.asyncio
    async def test_callback_raises_when_login_session_expired(self):
        service, deps = _make_service()
        deps["redis_client"].get = AsyncMock(return_value=None)

        with pytest.raises(LoginSessionExpiredError):
            await service.callback(code="code", state="state", login_session_id="sid")

    @pytest.mark.asyncio
    async def test_callback_raises_on_invalid_state(self):
        service, deps = _make_service()
        session_data = json.dumps({"csrf_token": "token-real", "code_verifier": "verifier"})
        deps["redis_client"].get = AsyncMock(return_value=session_data)
        deps["redis_client"].delete = AsyncMock()

        with pytest.raises(InvalidStateError):
            await service.callback(code="code", state="token-falso", login_session_id="sid")

    @pytest.mark.asyncio
    async def test_callback_returns_callback_response_on_success(self):
        service, deps = _make_service()

        csrf_token = "csrf-valido"
        session_data = json.dumps({
            "csrf_token": csrf_token,
            "code_verifier": "verifier",
            "app_state": {"next": "/home"},
        })
        deps["redis_client"].get = AsyncMock(return_value=session_data)
        deps["redis_client"].delete = AsyncMock()

        tokens = _make_tokens()
        deps["delta_client"].get_tokens = AsyncMock(return_value=tokens)

        user_info = _make_user_info()
        deps["token_validator"].validate.return_value = user_info

        session = _make_session()
        deps["session_service"].create = AsyncMock(return_value=session)

        result = await service.callback(code="code", state=csrf_token, login_session_id="login-sid")

        assert isinstance(result, DeltaCallbackResponse)
        assert result.session_id == session.id
        assert result.user_info == user_info
        assert result.app_state == {"next": "/home"}

    @pytest.mark.asyncio
    async def test_callback_deletes_login_session_from_redis(self):
        service, deps = _make_service()

        csrf_token = "csrf-valido"
        session_data = json.dumps({"csrf_token": csrf_token, "code_verifier": "verifier", "app_state": None})
        deps["redis_client"].get = AsyncMock(return_value=session_data)
        deps["redis_client"].delete = AsyncMock()
        deps["delta_client"].get_tokens = AsyncMock(return_value=_make_tokens())
        deps["token_validator"].validate.return_value = _make_user_info()
        deps["session_service"].create = AsyncMock(return_value=_make_session())

        await service.callback(code="code", state=csrf_token, login_session_id="login-sid")

        deps["redis_client"].delete.assert_called_once()


class TestGetSession:
    @pytest.mark.asyncio
    async def test_get_session_raises_when_session_not_found(self):
        service, deps = _make_service()
        deps["session_service"].get = AsyncMock(return_value=None)

        with pytest.raises(SessionNotFoundError):
            await service.get_session("session-inexistente")

    @pytest.mark.asyncio
    async def test_get_session_returns_valid_session(self):
        service, deps = _make_service()
        session = _make_session()
        deps["session_service"].get = AsyncMock(return_value=session)

        result = await service.get_session("session-id")

        assert result == session

    @pytest.mark.asyncio
    async def test_get_session_raises_when_access_token_expired_and_no_refresh_token(self):
        service, deps = _make_service()
        expired_session = _make_session(
            access_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
            refresh_token=None,
        )
        deps["session_service"].get = AsyncMock(return_value=expired_session)

        with pytest.raises(LoginSessionExpiredError):
            await service.get_session("session-id")

    @pytest.mark.asyncio
    async def test_get_session_refreshes_token_when_expired(self):
        service, deps = _make_service()

        expired_session = _make_session(
            access_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
            refresh_token="refresh-token",
        )
        refreshed_session = _make_session(
            access_token="novo-access-token",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        deps["session_service"].get = AsyncMock(return_value=expired_session)
        deps["session_service"].update = AsyncMock(return_value=refreshed_session)

        new_tokens = _make_tokens(access_token="novo-access-token", id_token=None)
        deps["delta_client"].refresh_tokens = AsyncMock(return_value=new_tokens)
        deps["token_validator"].validate.return_value = expired_session.user_info

        result = await service.get_session("session-id")

        assert result == refreshed_session
        deps["delta_client"].refresh_tokens.assert_called_once_with("refresh-token")

    @pytest.mark.asyncio
    async def test_get_session_skips_refresh_if_already_refreshed_inside_lock(self):
        service, deps = _make_service()

        expired_session = _make_session(
            access_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
            refresh_token="refresh-token",
        )
        already_refreshed_session = _make_session(
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        deps["session_service"].get = AsyncMock(side_effect=[expired_session, already_refreshed_session])

        result = await service.get_session("session-id")

        assert result == already_refreshed_session
        deps["delta_client"].refresh_tokens.assert_not_called()


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_deletes_session(self):
        service, deps = _make_service()
        deps["session_service"].delete = AsyncMock()

        await service.logout("session-id")

        deps["session_service"].delete.assert_called_once_with("session-id")
