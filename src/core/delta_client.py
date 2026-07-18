from urllib.parse import urlencode

import httpx

from core.exceptions import DeltaError, OAuthError, DeltaInternalError
from core.models import DeltaSettings, DeltaTokensResponse


class DeltaClient:
    def __init__(self, settings: DeltaSettings):
        self._settings = settings


    def get_login_url(
        self,
        code_challenge: str,
        code_challenge_method: str = "S256",
        login_hint: str | None = None,
        state: str | None = None,
    ) -> str:
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
                data = response.json()
                response.raise_for_status()
                return DeltaTokensResponse(
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
            raise DeltaInternalError(f"Delta API connection error: {e}") from e
