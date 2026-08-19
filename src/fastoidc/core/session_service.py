from datetime import datetime, timedelta, timezone
from secrets import token_hex
from typing import Any, Dict

from fastoidc.core.models import OIDCSession, OIDCTokensResponse
from fastoidc.stores import OIDCSessionStore
from fastoidc.utils.hashing import hash_string


class OIDCSessionService:
    """Service for managing the lifecycle of FastOIDC sessions."""

    def __init__(
        self,
        session_store: OIDCSessionStore,
        session_ttl_seconds: int,
    ):
        """Initializes the session service with the storage mechanism and session TTL."""
        self._session_store = session_store
        self._session_ttl_seconds = session_ttl_seconds


    async def create(
        self,
        tokens: OIDCTokensResponse,
        user_info: dict[str, Any],
        metadata: Dict[str, Any] | None = None,
        sid: str | None = None,
    ) -> OIDCSession:
        """Creates and stores a new session with the provided tokens and user info."""
        session_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._session_ttl_seconds)
        access_expires_seconds = tokens.expires_in if tokens.expires_in is not None else self._session_ttl_seconds
        access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=access_expires_seconds)
        
        session = OIDCSession(
            id=token_hex(32),
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_at=session_expires_at,
            access_token_expires_at=access_token_expires_at,
            token_type=tokens.token_type,
            scope=tokens.scope,
            user_info=user_info,
            metadata=metadata,
            id_token=tokens.id_token,
        )
        await self._session_store.create(session)
        if sid:
            await self._session_store.create_sid_index(hash_string(sid), session.id)
        return session

    
    async def get(self, session_id: str) -> OIDCSession | None:
        """Retrieves an active session by its identifier."""
        return await self._session_store.get(session_id)


    async def update(
        self,
        session_id: str,
        tokens: OIDCTokensResponse,
        user_info: dict[str, Any] | None = None,
    ) -> OIDCSession:
        """Updates the tokens, expiration, and optionally user info of an active session."""
        session = await self.get(session_id)
        if not session:
            raise ValueError("Session not found")

        session.access_token = tokens.access_token
        if tokens.refresh_token:
            session.refresh_token = tokens.refresh_token
            
        access_expires_seconds = tokens.expires_in if tokens.expires_in is not None else self._session_ttl_seconds
        session.access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=access_expires_seconds)
        session.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._session_ttl_seconds)

        if user_info:
            session.user_info = user_info

        if tokens.id_token:
            session.id_token = tokens.id_token

        await self._session_store.update(session)
        return session


    async def delete(self, session_id: str):
        """Deletes the session corresponding to the provided identifier."""
        await self._session_store.delete(session_id)


    async def touch(self, session: OIDCSession) -> OIDCSession:
        """Renews the session expiration without modifying tokens."""
        session.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._session_ttl_seconds)
        await self._session_store.update(session)
        return session


    async def delete_by_sid(self, sid_hash: str) -> bool:
        """Deletes the session associated with the given IdP session ID hash."""
        return await self._session_store.delete_by_sid(sid_hash)
