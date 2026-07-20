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
