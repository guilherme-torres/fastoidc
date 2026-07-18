from dataclasses import dataclass
from datetime import datetime
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
    session_ttl_seconds: int
    issuer: str | None = None
    audience: str | None = None


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
class DeltaUserInfo:
    sub: str
    username: str | None = None
    email: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    name: str | None = None
    picture: str | None = None


@dataclass
class DeltaSession:
    id: str
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    access_token_expires_at: datetime
    token_type: str
    scope: str
    user_info: DeltaUserInfo | None
    metadata: dict[str, Any] | None = None


@dataclass
class DeltaCallbackResponse:
    session_id: str
    user_info: DeltaUserInfo
    app_state: Dict[str, Any] | None
