from typing import Any

import jwt
from jwt import PyJWKClient

from fastoidc.exceptions import OIDCError


class TokenValidator:
    """Validator for ID tokens (JWT) issued by the FastOIDC authorization server."""

    def __init__(
        self,
        jwk_client: PyJWKClient,
        issuer: str,
        audience: str,
    ):
        """Initializes the validator with the JWK client, expected issuer, and audience."""
        self._jwk_client = jwk_client
        self._issuer = issuer
        self._audience = audience


    def validate(self, id_token: str | None) -> dict[str, Any]:
        """Validates the ID token and returns the user profile information."""
        if id_token is None:
            raise OIDCError("ID token was not returned by the authorization server")

        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(id_token)

            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
            )

            return claims
        except jwt.PyJWTError as e:
            raise OIDCError(f"Invalid or expired ID token: {e}") from e


    def validate_logout_token(self, logout_token: str) -> str:
        """Validates a Back-Channel Logout Token and returns the sid claim."""
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(logout_token)

            claims = jwt.decode(
                logout_token,
                signing_key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
            )

            events = claims.get("events")
            if not events or "http://schemas.openid.net/event/backchannel-logout" not in events:
                raise OIDCError("Missing or invalid 'events' claim in logout token")

            sid = claims.get("sid")
            if not sid:
                raise OIDCError("Missing 'sid' claim in logout token")

            if "nonce" in claims:
                raise OIDCError("Logout token must not contain a 'nonce' claim")

            return sid
        except jwt.PyJWTError as e:
            raise OIDCError(f"Invalid or expired logout token: {e}") from e
