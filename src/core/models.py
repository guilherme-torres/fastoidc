from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class DeltaSettings:
    client_id: str
    client_secret: str
    redirect_uri: str
    token_endpoint: str
    authorization_endpoint: str
    jwks_endpoint: str
    scopes: str


@dataclass
class DeltaTokensResponse:
    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str | None = None


@dataclass
class DeltaLoginResponse:
    login_url: str
    login_session_id: str
    login_session_ttl: int


@dataclass
class DeltaCallbackResponse:
    tokens: DeltaTokensResponse
    app_state: Dict[str, Any] | None
