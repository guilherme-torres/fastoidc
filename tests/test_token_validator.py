import pytest
from unittest.mock import MagicMock, patch

import jwt

from fastoidc.core.exceptions import OIDCError
from fastoidc.core.models import OIDCUserInfo
from fastoidc.core.token_validator import TokenValidator


def _make_validator():
    mock_jwk_client = MagicMock()
    return TokenValidator(
        jwk_client=mock_jwk_client,
        issuer="https://idp.empresa.com",
        audience="client-id",
    )


def test_validate_raises_when_id_token_is_none():
    validator = _make_validator()
    with pytest.raises(OIDCError, match="ID token was not returned"):
        validator.validate(None)


def test_validate_returns_user_info_on_valid_token():
    validator = _make_validator()
    mock_key = MagicMock()
    validator._jwk_client.get_signing_key_from_jwt.return_value = mock_key

    claims = {
        "sub": "user-123",
        "email": "user@empresa.com",
        "name": "Guilherme Torres",
        "given_name": "Guilherme",
        "family_name": "Torres",
        "username": "guilherme",
        "picture": "https://cdn.empresa.com/foto.jpg",
    }

    with patch("jwt.decode", return_value=claims):
        result = validator.validate("token-valido")

    assert isinstance(result, OIDCUserInfo)
    assert result.sub == "user-123"
    assert result.email == "user@empresa.com"
    assert result.name == "Guilherme Torres"
    assert result.given_name == "Guilherme"
    assert result.family_name == "Torres"
    assert result.username == "guilherme"
    assert result.picture == "https://cdn.empresa.com/foto.jpg"


def test_validate_raises_delta_error_on_jwt_error():
    validator = _make_validator()
    validator._jwk_client.get_signing_key_from_jwt.side_effect = jwt.PyJWTError("assinatura inválida")

    with pytest.raises(OIDCError, match="Invalid or expired ID token"):
        validator.validate("token-invalido")


def test_validate_partial_claims_are_none():
    validator = _make_validator()
    mock_key = MagicMock()
    validator._jwk_client.get_signing_key_from_jwt.return_value = mock_key

    with patch("jwt.decode", return_value={"sub": "user-456"}):
        result = validator.validate("token-parcial")

    assert result.sub == "user-456"
    assert result.email is None
    assert result.name is None
