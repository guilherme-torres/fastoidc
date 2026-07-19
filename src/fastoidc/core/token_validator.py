import jwt
from jwt import PyJWKClient

from fastoidc.core.models import OIDCUserInfo
from fastoidc.core.exceptions import OIDCError


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

    def validate(self, id_token: str | None) -> OIDCUserInfo:
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

            return OIDCUserInfo(
                sub=claims.get("sub"),
                username=claims.get("username"),
                email=claims.get("email"),
                given_name=claims.get("given_name"),
                family_name=claims.get("family_name"),
                name=claims.get("name"),
                picture=claims.get("picture"),
            )
        except jwt.PyJWTError as e:
            raise OIDCError(f"Invalid or expired ID token: {e}") from e
