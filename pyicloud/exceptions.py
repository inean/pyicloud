"""Library exceptions."""

from pydantic import ValidationError


class PyiCloudError(Exception):
    """Generic iCloud exception."""


PyiCloudValidationError = ValidationError


class PyiCloudUserCancelledError(PyiCloudError):
    def __init__(self, message: str = "User cancelled the operation"):
        super().__init__(message)


class PyiCloudAPIResponseError(PyiCloudError):
    """iCloud response exception."""

    def __init__(self, reason, code=None, retry=False):
        self.reason = reason
        self.code = code
        message = reason or ""
        if code:
            message += " (%s)" % code
        if retry:
            message += ". Retrying ..."

        super().__init__(message)


class PyiCloudServiceNotActivatedException(PyiCloudAPIResponseError):
    """iCloud service not activated exception."""


# Login
class PyiCloudFailedLoginException(PyiCloudError):
    """iCloud failed login exception."""


class PyiCloud2SARequiredException(PyiCloudError):
    """iCloud 2SA required exception."""

    def __init__(self, apple_id):
        message = "Two-step authentication required for account: %s" % apple_id
        super().__init__(message)


class PyiCloudNoStoredPasswordAvailableException(PyiCloudError):
    """iCloud no stored password exception."""


# Webservice specific
class PyiCloudNoDevicesException(PyiCloudError):
    """iCloud no device exception."""
