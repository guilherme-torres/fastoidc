import json
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from fastoidc.exceptions import SessionNotFoundError
from fastoidc.core.models import OIDCSession, OIDCTokensResponse
from fastoidc.core.session_service import OIDCSessionService


def _make_tokens(**overrides) -> OIDCTokensResponse:
    defaults = dict(
        access_token="access-token",
        id_token="id-token",
        refresh_token="refresh-token",
        token_type="Bearer",
        expires_in=3600,
        scope="openid profile",
    )
    return OIDCTokensResponse(**{**defaults, **overrides})


def _make_session(**overrides) -> OIDCSession:
    defaults = dict(
        id="session-id",
        access_token="access-token",
        refresh_token="refresh-token",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        token_type="Bearer",
        scope="openid profile",
        user_info={"sub": "user-123"},
    )
    return OIDCSession(**{**defaults, **overrides})


def _make_service(session_ttl_seconds=3600):
    store = AsyncMock()
    service = OIDCSessionService(session_store=store, session_ttl_seconds=session_ttl_seconds)
    return service, store


class TestCreate:
    @pytest.mark.asyncio
    async def test_create_saves_session_in_store(self):
        service, store = _make_service()
        store.create = AsyncMock()

        tokens = _make_tokens()
        user_info = {"sub": "user-123"}

        result = await service.create(tokens=tokens, user_info=user_info)

        store.create.assert_called_once_with(result)

    @pytest.mark.asyncio
    async def test_create_sets_correct_expiration_times(self):
        service, store = _make_service(session_ttl_seconds=7200)
        store.create = AsyncMock()

        tokens = _make_tokens(expires_in=60)
        user_info = {"sub": "user-123"}

        before = datetime.now(timezone.utc)
        result = await service.create(tokens=tokens, user_info=user_info)
        after = datetime.now(timezone.utc)

        assert before + timedelta(seconds=55) < result.access_token_expires_at < after + timedelta(seconds=65)
        assert before + timedelta(seconds=7195) < result.expires_at < after + timedelta(seconds=7205)

    @pytest.mark.asyncio
    async def test_create_returns_session_with_correct_data(self):
        service, store = _make_service()
        store.create = AsyncMock()

        tokens = _make_tokens(access_token="meu-token", refresh_token="meu-refresh")
        user_info = {"sub": "user-abc"}

        result = await service.create(tokens=tokens, user_info=user_info)

        assert result.access_token == "meu-token"
        assert result.refresh_token == "meu-refresh"
        assert result.user_info == user_info
        assert result.id is not None


class TestGet:
    @pytest.mark.asyncio
    async def test_get_returns_session_from_store(self):
        service, store = _make_service()
        session = _make_session()
        store.get = AsyncMock(return_value=session)

        result = await service.get("session-id")

        assert result == session
        store.get.assert_called_once_with("session-id")

    @pytest.mark.asyncio
    async def test_get_returns_none_when_session_not_found(self):
        service, store = _make_service()
        store.get = AsyncMock(return_value=None)

        result = await service.get("inexistente")

        assert result is None


class TestUpdate:
    @pytest.mark.asyncio
    async def test_update_raises_when_session_not_found(self):
        service, store = _make_service()
        store.get = AsyncMock(return_value=None)

        with pytest.raises(ValueError, match="Session not found"):
            await service.update(session_id="inexistente", tokens=_make_tokens())

    @pytest.mark.asyncio
    async def test_update_refreshes_tokens(self):
        service, store = _make_service()
        session = _make_session()
        store.get = AsyncMock(return_value=session)
        store.update = AsyncMock()

        new_tokens = _make_tokens(access_token="novo-access", refresh_token="novo-refresh")
        result = await service.update(session_id="session-id", tokens=new_tokens)

        assert result.access_token == "novo-access"
        assert result.refresh_token == "novo-refresh"
        store.update.assert_called_once_with(result)

    @pytest.mark.asyncio
    async def test_update_does_not_overwrite_refresh_token_when_none(self):
        service, store = _make_service()
        session = _make_session(refresh_token="refresh-original")
        store.get = AsyncMock(return_value=session)
        store.update = AsyncMock()

        new_tokens = _make_tokens(access_token="novo-access", refresh_token=None)
        result = await service.update(session_id="session-id", tokens=new_tokens)

        assert result.refresh_token == "refresh-original"

    @pytest.mark.asyncio
    async def test_update_replaces_user_info_when_provided(self):
        service, store = _make_service()
        session = _make_session()
        store.get = AsyncMock(return_value=session)
        store.update = AsyncMock()

        new_user_info = {"sub": "user-novo", "email": "novo@empresa.com"}
        result = await service.update(session_id="session-id", tokens=_make_tokens(), user_info=new_user_info)

        assert result.user_info == new_user_info


class TestDelete:
    @pytest.mark.asyncio
    async def test_delete_calls_store_delete(self):
        service, store = _make_service()
        store.delete = AsyncMock()

        await service.delete("session-id")

        store.delete.assert_called_once_with("session-id")
