from abc import ABC, abstractmethod

from fastoidc.core.models import OIDCSession


class OIDCSessionStore(ABC):

    @abstractmethod
    async def create(self, session: OIDCSession):
        ...

    @abstractmethod
    async def get(self, session_id: str) -> OIDCSession | None:
        ...

    @abstractmethod
    async def update(self, session: OIDCSession):
        ...

    @abstractmethod
    async def delete(self, session_id: str):
        ...

    @abstractmethod
    async def create_sid_index(self, sid_hash: str, session_id: str):
        ...

    @abstractmethod
    async def delete_by_sid(self, sid_hash: str) -> bool:
        ...
