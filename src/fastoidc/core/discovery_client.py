import httpx

from fastoidc.exceptions import OIDCInternalError


class DiscoveryClient:
    """Fetches the OpenID Connect discovery document."""

    def __init__(self, discovery_url: str):
        self._discovery_url = discovery_url
        self._cache: dict | None = None

    def get(self) -> dict:
        """Returns the discovery document, caching it in memory for the lifetime of the instance."""
        if self._cache is None:
            self._cache = self._fetch()
        return self._cache

    def _fetch(self) -> dict:
        try:
            with httpx.Client() as client:
                response = client.get(self._discovery_url)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as e:
            raise OIDCInternalError(f"Discovery endpoint returned error: {e}") from e
        except httpx.RequestError as e:
            raise OIDCInternalError(f"Failed to reach discovery endpoint: {e}") from e
