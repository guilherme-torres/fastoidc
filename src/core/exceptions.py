class DeltaError(Exception):
    pass


class AuthenticationError(DeltaError):
    pass


class InvalidStateError(AuthenticationError):
    pass


class LoginSessionExpiredError(AuthenticationError):
    pass


class OAuthError(AuthenticationError):
    pass


class DeltaInternalError(DeltaError):
    pass
