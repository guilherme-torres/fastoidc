class OIDCError(Exception):
    """Base exception for all errors in the FastOIDC library."""
    pass


class AuthenticationError(OIDCError):
    """General error raised during the authentication or validation process."""
    pass


class InvalidStateError(AuthenticationError):
    """Error raised when the state (CSRF) parameter does not match the expected value."""
    pass


class LoginSessionExpiredError(AuthenticationError):
    """Error raised when the temporary login session has expired or does not exist."""
    pass


class OAuthError(AuthenticationError):
    """Error raised when an OAuth/OIDC protocol request fails."""
    pass


class OIDCInternalError(OIDCError):
    """Internal library error or unexpected connection failure with the FastOIDC servers."""
    pass


class SessionNotFoundError(AuthenticationError):
    """Error raised when an active user session is not found in the store."""
    pass
