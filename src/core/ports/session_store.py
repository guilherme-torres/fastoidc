from abc import ABC, abstractmethod

from core.models import DeltaSession


class DeltaSessionStore(ABC):

    @abstractmethod
    async def create(self, session: DeltaSession):
        ...

    @abstractmethod
    async def get(self, session_id: str) -> DeltaSession | None:
        ...

    @abstractmethod
    async def update(self, session: DeltaSession):
        ...

    @abstractmethod
    async def delete(self, session_id: str):
        ...
