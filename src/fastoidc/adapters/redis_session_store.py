import json
from dataclasses import asdict
from datetime import datetime

import redis.asyncio as redis

from fastoidc.core.ports.session_store import OIDCSessionStore
from fastoidc.core.models import OIDCSession, OIDCUserInfo
from fastoidc.utils.hashing import hash_string


class RedisSessionStore(OIDCSessionStore):
    """Redis-backed session store implementation for FastOIDC sessions."""

    def __init__(self, redis_client: redis.Redis, session_key_prefix: str = "session:"):
        """Initializes the Redis session store with a Redis client and optional key prefix."""
        self.redis_client = redis_client
        self.session_key_prefix = session_key_prefix

    def _get_key(self, session_id: str) -> str:
        """Helper to build a prefixed and hashed Redis key from a session ID."""
        return f"{self.session_key_prefix}{hash_string(session_id)}"

    def _serialize(self, session: OIDCSession) -> str:
        """Serializes a OIDCSession instance to a JSON string representation."""
        data = asdict(session)
        if session.expires_at:
            data["expires_at"] = session.expires_at.isoformat()
        if session.access_token_expires_at:
            data["access_token_expires_at"] = session.access_token_expires_at.isoformat()
        return json.dumps(data)

    def _deserialize(self, data_str: str) -> OIDCSession:
        """Deserializes a JSON string representation back to a OIDCSession instance."""
        data = json.loads(data_str)
        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        if data.get("access_token_expires_at"):
            data["access_token_expires_at"] = datetime.fromisoformat(data["access_token_expires_at"])
        if data.get("user_info") is not None:
            data["user_info"] = OIDCUserInfo(**data["user_info"])
        return OIDCSession(**data)

    async def create(self, session: OIDCSession):
        """Persists a new OIDCSession in Redis with its corresponding TTL expiration."""
        key = self._get_key(session.id)
        await self.redis_client.set(key, self._serialize(session))
        if session.expires_at:
            await self.redis_client.expireat(key, int(session.expires_at.timestamp()))

    async def get(self, session_id: str) -> OIDCSession | None:
        """Retrieves and deserializes a OIDCSession from Redis by its session ID."""
        key = self._get_key(session_id)
        data_str = await self.redis_client.get(key)
        if data_str:
            return self._deserialize(data_str)
        return None

    async def update(self, session: OIDCSession):
        """Updates an existing OIDCSession in Redis."""
        await self.create(session)

    async def delete(self, session_id: str):
        """Removes a OIDCSession from Redis by its session ID."""
        key = self._get_key(session_id)
        await self.redis_client.delete(key)
