from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass
class OIDCSettings:
    """Configuration settings required to interact with the FastOIDC OIDC provider."""
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
class OIDCTokensResponse:
    """Token response schema returned by the FastOIDC token endpoint."""
    access_token: str
    id_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str | None = None


@dataclass
class OIDCLoginResponse:
    """Response data containing login URL and session ID to initiate login flow."""
    login_url: str
    login_session_id: str
    login_session_ttl: int


@dataclass
class OIDCUserInfo:
    """User profile information extracted and validated from the ID token."""
    sub: str
    username: str | None = None
    email: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    name: str | None = None
    picture: str | None = None


@dataclass
class OIDCSession:
    """Represents an active user session, storing associated tokens and validation states."""
    id: str
    access_token: str
    refresh_token: str | None
    expires_at: datetime
    access_token_expires_at: datetime
    token_type: str
    scope: str
    user_info: OIDCUserInfo | None
    metadata: dict[str, Any] | None = None


@dataclass
class OIDCCallbackResponse:
    """Data returned after successfully processing the authentication callback."""
    session_id: str
    user_info: OIDCUserInfo
    app_state: Dict[str, Any] | None
