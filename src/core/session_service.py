from datetime import datetime, timedelta, timezone
from secrets import token_hex
from typing import Any, Dict

from core.models import DeltaSession, DeltaTokensResponse, DeltaUserInfo
from core.ports.session_store import DeltaSessionStore


class DeltaSessionService:
    def __init__(
        self,
        session_store: DeltaSessionStore,
        session_ttl_seconds: int,
    ):
        self._session_store = session_store
        self._session_ttl_seconds = session_ttl_seconds

    async def create(
        self,
        tokens: DeltaTokensResponse,
        user_info: DeltaUserInfo,
        metadata: Dict[str, Any] | None = None,
    ) -> DeltaSession:
        session_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._session_ttl_seconds)
        access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=tokens.expires_in)
        session = DeltaSession(
            id=token_hex(32),
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_at=session_expires_at,
            access_token_expires_at=access_token_expires_at,
            token_type=tokens.token_type,
            scope=tokens.scope,
            user_info=user_info,
            metadata=metadata,
        )
        await self._session_store.create(session)
        return session
    
    async def get(self, session_id: str) -> DeltaSession | None:
        return await self._session_store.get(session_id)

    async def update(
        self,
        session_id: str,
        tokens: DeltaTokensResponse,
        user_info: DeltaUserInfo | None = None,
    ) -> DeltaSession:
        session = await self.get(session_id)
        if not session:
            raise ValueError("Session not found")

        session.access_token = tokens.access_token
        if tokens.refresh_token:
            session.refresh_token = tokens.refresh_token
            
        session.access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=tokens.expires_in)
        session.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._session_ttl_seconds)

        if user_info:
            session.user_info = user_info

        await self._session_store.update(session)
        return session
