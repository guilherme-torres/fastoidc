from urllib.parse import urlencode

import httpx

from fastoidc.exceptions import OAuthError, OIDCInternalError
from fastoidc.core.models import OIDCSettings, OIDCTokensResponse


class OIDCClient:
    """HTTP client to perform direct OIDC queries and calls to the FastOIDC authorization server."""

    def __init__(self, settings: OIDCSettings):
        """Initializes the FastOIDC client with endpoint configurations and credentials."""
        self._settings = settings


    def get_login_url(
        self,
        code_challenge: str,
        code_challenge_method: str = "S256",
        login_hint: str | None = None,
        state: str | None = None,
    ) -> str:
        """Generates the authorization URL to initiate the OIDC authorization code flow."""
        url_params = {
            "response_type": "code",
            "client_id": self._settings.client_id,
            "scope": self._settings.scopes,
            "redirect_uri": self._settings.redirect_uri,
        }
        if login_hint:
            url_params["login_hint"] = login_hint
        if state:
            url_params["state"] = state
        if code_challenge:
            url_params["code_challenge"] = code_challenge
            url_params["code_challenge_method"] = code_challenge_method
        return f"{self._settings.authorization_endpoint}?{urlencode(url_params)}"
    

    async def get_tokens(
        self,
        auth_code: str,
        code_verifier: str | None = None,
    ):
        """Exchanges an authorization code for access, ID, and refresh tokens."""
        payload = {
            "code": auth_code,
            "grant_type": "authorization_code",
            "redirect_uri": self._settings.redirect_uri,
            "client_id": self._settings.client_id,
            "client_secret": self._settings.client_secret,
        }
        if code_verifier:
            payload["code_verifier"] = code_verifier
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=self._settings.token_endpoint,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=payload,
                )
                response.raise_for_status()
                data = response.json()
                return OIDCTokensResponse(
                    access_token=data.get("access_token"),
                    refresh_token=data.get("refresh_token"),
                    scope=data.get("scope"),
                    id_token=data.get("id_token"),
                    token_type=data.get("token_type"),
                    expires_in=data.get("expires_in"),
                )
        except httpx.HTTPStatusError as e:
            raise OAuthError(f"OAuth request failed: {e}") from e
        except httpx.RequestError as e:
            raise OIDCInternalError(f"FastOIDC API connection error: {e}") from e
    

    async def refresh_tokens(self, refresh_token: str):
        """Uses a refresh token to obtain a new set of active tokens."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url=self._settings.token_endpoint,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                    },
                    auth=httpx.BasicAuth(
                        username=self._settings.client_id,
                        password=self._settings.client_secret,
                    ),
                )
                response.raise_for_status()
                data = response.json()
                return OIDCTokensResponse(
                    access_token=data.get("access_token"),
                    refresh_token=data.get("refresh_token"),
                    scope=data.get("scope"),
                    id_token=data.get("id_token"),
                    token_type=data.get("token_type"),
                    expires_in=data.get("expires_in"),
                )
        except httpx.HTTPStatusError as e:
            raise OAuthError(f"OAuth request failed: {e}") from e
        except httpx.RequestError as e:
            raise OIDCInternalError(f"FastOIDC API connection error: {e}") from e


    def get_logout_url(self, id_token_hint: str, state: str | None = None) -> str:
        """Builds the URL for RP-Initiated Logout at the IdP."""
        if not self._settings.logout_endpoint:
            raise OIDCInternalError("logout_endpoint is not configured in OIDCSettings")

        payload = {"id_token_hint": id_token_hint}
        if self._settings.post_logout_redirect_uri:
            payload["post_logout_redirect_uri"] = self._settings.post_logout_redirect_uri
        if state:
            payload["state"] = state

        return f"{self._settings.logout_endpoint}?{urlencode(payload)}"
