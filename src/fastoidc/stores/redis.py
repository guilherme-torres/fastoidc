import json
from dataclasses import asdict
from datetime import datetime

import redis.asyncio as redis

from fastoidc.stores.base import OIDCSessionStore
from fastoidc.core.models import OIDCSession
from fastoidc.utils.hashing import hash_string


class RedisSessionStore(OIDCSessionStore):

    SID_KEY_PREFIX = "fastoidc:sid:"


    def __init__(self, redis_client: redis.Redis, session_key_prefix: str = "fastoidc:session:"):
        self.redis_client = redis_client
        self.session_key_prefix = session_key_prefix


    def _get_key(self, session_id: str) -> str:
        return f"{self.session_key_prefix}{hash_string(session_id)}"


    def _serialize(self, session: OIDCSession) -> str:
        data = asdict(session)
        if session.expires_at:
            data["expires_at"] = session.expires_at.isoformat()
        if session.access_token_expires_at:
            data["access_token_expires_at"] = session.access_token_expires_at.isoformat()
        return json.dumps(data)


    def _deserialize(self, data_str: str) -> OIDCSession:
        data = json.loads(data_str)
        if data.get("expires_at"):
            data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        if data.get("access_token_expires_at"):
            data["access_token_expires_at"] = datetime.fromisoformat(data["access_token_expires_at"])
        return OIDCSession(**data)


    async def create(self, session: OIDCSession):
        key = self._get_key(session.id)
        await self.redis_client.set(key, self._serialize(session))
        if session.expires_at:
            await self.redis_client.expireat(key, int(session.expires_at.timestamp()))


    async def get(self, session_id: str) -> OIDCSession | None:
        key = self._get_key(session_id)
        data_str = await self.redis_client.get(key)
        if data_str:
            return self._deserialize(data_str)
        return None


    async def update(self, session: OIDCSession):
        await self.create(session)


    async def delete(self, session_id: str):
        key = self._get_key(session_id)
        await self.redis_client.delete(key)


    async def create_sid_index(self, sid_hash: str, session_id: str):
        sid_key = f"{self.SID_KEY_PREFIX}{sid_hash}"
        session_key = self._get_key(session_id)
        await self.redis_client.set(sid_key, session_key)


    async def delete_by_sid(self, sid_hash: str) -> bool:
        sid_key = f"{self.SID_KEY_PREFIX}{sid_hash}"
        session_key = await self.redis_client.get(sid_key)
        if not session_key:
            return False
        await self.redis_client.delete(session_key)
        await self.redis_client.delete(sid_key)
        return True
