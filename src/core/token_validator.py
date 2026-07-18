import jwt
from jwt import PyJWKClient

from core.models import DeltaUserInfo
from core.exceptions import DeltaError


class TokenValidator:
    def __init__(
        self,
        jwk_client: PyJWKClient,
        issuer: str,
        audience: str,
    ):
        self._jwk_client = jwk_client
        self._issuer = issuer
        self._audience = audience

    def validate(self, id_token: str | None) -> DeltaUserInfo:
        if id_token is None:
            raise DeltaError("ID token was not returned by the authorization server")

        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(id_token)

            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
            )

            return DeltaUserInfo(
                sub=claims.get("sub"),
                username=claims.get("username"),
                email=claims.get("email"),
                given_name=claims.get("given_name"),
                family_name=claims.get("family_name"),
                name=claims.get("name"),
                picture=claims.get("picture"),
            )
        except jwt.PyJWTError as e:
            raise DeltaError(f"Invalid or expired ID token: {e}") from e
