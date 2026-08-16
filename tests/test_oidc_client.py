import pytest

from fastoidc.core.oidc_client import OIDCClient
from fastoidc.core.models import OIDCSettings
from fastoidc.exceptions import OIDCInternalError


def _make_settings(**overrides) -> OIDCSettings:
    defaults = dict(
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="https://app.empresa.com/auth/callback",
        token_endpoint="https://idp.empresa.com/token",
        authorization_endpoint="https://idp.empresa.com/auth",
        jwks_endpoint="https://idp.empresa.com/certs",
        scopes="openid profile",
        session_ttl_seconds=3600,
        issuer="https://idp.empresa.com",
        logout_endpoint="https://idp.empresa.com/logout",
        post_logout_redirect_uri="https://app.empresa.com/logged-out",
    )
    return OIDCSettings(**{**defaults, **overrides})


class TestGetLogoutUrl:
    def test_get_logout_url_raises_when_logout_endpoint_not_configured(self):
        settings = _make_settings(logout_endpoint=None)
        client = OIDCClient(settings)

        with pytest.raises(OIDCInternalError):
            client.get_logout_url(id_token_hint="some-id-token")

    def test_get_logout_url_builds_url_correctly(self):
        settings = _make_settings()
        client = OIDCClient(settings)

        url = client.get_logout_url(id_token_hint="some-id-token")

        assert url.startswith("https://idp.empresa.com/logout?")
        assert "id_token_hint=some-id-token" in url
        assert "post_logout_redirect_uri=https%3A%2F%2Fapp.empresa.com%2Flogged-out" in url
        assert "state=" not in url

    def test_get_logout_url_includes_state_when_provided(self):
        settings = _make_settings()
        client = OIDCClient(settings)

        url = client.get_logout_url(id_token_hint="some-id-token", state="logout-state")

        assert "state=logout-state" in url

    def test_get_logout_url_omits_post_logout_redirect_uri_when_not_configured(self):
        settings = _make_settings(post_logout_redirect_uri=None)
        client = OIDCClient(settings)

        url = client.get_logout_url(id_token_hint="some-id-token")

        assert "id_token_hint=some-id-token" in url
        assert "post_logout_redirect_uri" not in url
