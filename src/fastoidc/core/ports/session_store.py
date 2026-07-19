from abc import ABC, abstractmethod

from fastoidc.core.models import OIDCSession


class OIDCSessionStore(ABC):
    """Abstract interface for storing and managing FastOIDC sessions."""

    @abstractmethod
    async def create(self, session: OIDCSession):
        """Creates a new session in the store."""
        ...

    @abstractmethod
    async def get(self, session_id: str) -> OIDCSession | None:
        """Retrieves a session from the store by its ID."""
        ...

    @abstractmethod
    async def update(self, session: OIDCSession):
        """Updates an existing session in the store."""
        ...

    @abstractmethod
    async def delete(self, session_id: str):
        """Deletes a session from the store by its ID."""
        ...
