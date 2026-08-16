class OIDCError(Exception):
    pass


class AuthenticationError(OIDCError):
    pass


class InvalidStateError(AuthenticationError):
    pass


class LoginSessionExpiredError(AuthenticationError):
    pass


class OAuthError(AuthenticationError):
    pass


class OIDCInternalError(OIDCError):
    pass


class SessionNotFoundError(AuthenticationError):
    pass


class BackchannelLogoutError(OIDCError):
    pass
