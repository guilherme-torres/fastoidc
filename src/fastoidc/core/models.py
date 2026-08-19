from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class OIDCSettings:
    """Configuration settings required to interact with the FastOIDC OIDC provider."""
    client_id: str
    client_secret: str
    redirect_uri: str
    token_endpoint: str
    authorization_endpoint: str
    scopes: str
    jwks_endpoint: str | None = None
    issuer: str | None = None
    audience: str | None = None
    session_ttl_seconds: int = 86400
    logout_endpoint: str | None = None
    post_logout_redirect_uri: str | None = None
    userinfo_endpoint: str | None = None


@dataclass
class OIDCTokensResponse:
    """Token response schema returned by the FastOIDC token endpoint."""
    access_token: str
    token_type: str
    expires_in: int | None = None
    scope: str | None = None
    id_token: str | None = None
    refresh_token: str | None = None
    refresh_token_expires_in: int | None = None


@dataclass
class OIDCLoginResponse:
    """Response data containing login URL and session ID to initiate login flow."""
    login_url: str
    login_session_id: str
    login_session_ttl: int


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
    user_info: dict[str, Any] | None
    metadata: dict[str, Any] | None = None
    id_token: str | None = None


@dataclass
class OIDCCallbackResponse:
    """Data returned after successfully processing the authentication callback."""
    session_id: str
    user_info: dict[str, Any]
    app_state: Any
