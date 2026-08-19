from unittest.mock import MagicMock, patch

import httpx
import pytest

from fastoidc.core.discovery_client import DiscoveryClient
from fastoidc.exceptions import OIDCInternalError

SAMPLE_DOCUMENT = {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    "end_session_endpoint": "https://oauth2.googleapis.com/revoke",
    "id_token_signing_alg_values_supported": ["RS256"],
}

def make_mock_response(data: dict, status_code: int = 200):
    mock = MagicMock()
    mock.json.return_value = data
    mock.raise_for_status = MagicMock()
    if status_code >= 400:
        mock.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=MagicMock()
        )
    return mock


def test_get_fetches_document_on_first_call():
    client = DiscoveryClient("https://example.com/.well-known/openid-configuration")
    mock_response = make_mock_response(SAMPLE_DOCUMENT)

    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.get.return_value = mock_response
        mock_client_cls.return_value.__enter__.return_value = mock_http

        doc = client.get()

    assert doc["issuer"] == "https://accounts.google.com"
    assert doc["token_endpoint"] == "https://oauth2.googleapis.com/token"
    mock_http.get.assert_called_once()


def test_get_uses_cache_on_second_call():
    client = DiscoveryClient("https://example.com/.well-known/openid-configuration")
    mock_response = make_mock_response(SAMPLE_DOCUMENT)

    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.get.return_value = mock_response
        mock_client_cls.return_value.__enter__.return_value = mock_http

        client.get()
        client.get()

    assert mock_http.get.call_count == 1


def test_get_raises_oidc_internal_error_on_http_status_error():
    client = DiscoveryClient("https://example.com/.well-known/openid-configuration")
    mock_response = make_mock_response({}, status_code=500)

    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.get.return_value = mock_response
        mock_client_cls.return_value.__enter__.return_value = mock_http

        with pytest.raises(OIDCInternalError, match="Discovery endpoint returned error"):
            client.get()


def test_get_raises_oidc_internal_error_on_connection_error():
    client = DiscoveryClient("https://example.com/.well-known/openid-configuration")

    with patch("httpx.Client") as mock_client_cls:
        mock_http = MagicMock()
        mock_http.get.side_effect = httpx.RequestError("connection failed")
        mock_client_cls.return_value.__enter__.return_value = mock_http

        with pytest.raises(OIDCInternalError, match="Failed to reach discovery endpoint"):
            client.get()
