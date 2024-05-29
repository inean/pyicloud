import logging
from typing import Any
from weakref import ReferenceType, ref

from pyicloud.utils.decorators import deprecated

# Use the package name as the logger name
__package_name__ = __name__.partition(".")[0]

# Define a logger for the package
LOGGER = logging.getLogger(__package_name__)


@deprecated
def log_request(func):
    def wrapper(self, method, url, **kwargs):
        # Charge logging to the right service endpoint
        logger = logger_get("http")
        logger.debug("%s %s %s", method, url, kwargs.get("data", ""))
        return func(self, method, url, logger, **kwargs)

    return wrapper


def logger_get(name: str) -> logging.Logger:
    """Get a logger for the given name."""
    return logging.getLogger(__package_name__).getChild(name)


def hide_sensitive_data(value: str, logger: logging.Logger | str = "") -> str:
    if isinstance(logger, str):
        logger = logger_get(logger) if logger else LOGGER
    log_record = logging.makeLogRecord({"msg": value})
    if not logger.filter(log_record):
        AssertionError("The logger did not filter the message")
    return log_record.getMessage()


class PyiCloudPasswordFilter(logging.Filter):
    """Password log hider."""

    _ACTIVE_FILTERS: dict[logging.Logger, dict[ref, logging.Filter | None]] = {}

    @classmethod
    def register(cls, instance: object, logger: logging.Logger = LOGGER):
        """Register the object to the active filters."""
        if logger not in cls._ACTIVE_FILTERS:
            cls._ACTIVE_FILTERS[logger] = {}
        # Store a weak reference to the instance
        instance = ref(instance, cls.unregister)
        assert instance not in cls._ACTIVE_FILTERS[logger]
        cls._ACTIVE_FILTERS[logger][instance] = None

    @classmethod
    def unregister(cls, instance: object):
        """Remove the object from the active filters."""
        weak_ref = instance if isinstance(instance, ReferenceType) else ref(instance)
        for logger in cls._ACTIVE_FILTERS:
            if weak_ref in cls._ACTIVE_FILTERS[logger]:
                if password_filter := cls._ACTIVE_FILTERS[logger].pop(weak_ref):
                    logger.removeFilter(password_filter)

    @classmethod
    def on_changed_password(cls, value: Any, context: object):
        """Update the password for the active filters."""

        # Parse value, it may be a string or a SecretStr
        if hasattr(value, "get_secret_value"):
            password = value.get_secret_value()
        if isinstance(value, str):
            password = value

        if password:
            for logger in cls._ACTIVE_FILTERS:
                for weak_ref, password_filter in cls._ACTIVE_FILTERS[logger].items():
                    if weak_ref() == context:
                        if not isinstance(password_filter, cls):
                            password_filter = cls(password)
                            cls._ACTIVE_FILTERS[logger][weak_ref] = password_filter
                            logger.addFilter(password_filter)
                        else:
                            # Update the password for the filter
                            password_filter.name = password

    def __init__(self, password):
        super().__init__(password)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        if self.name in message:
            name_length = len(self.name)
            mask_length = min(8, name_length - 1)
            masked_name = "*" * mask_length + self.name[mask_length:]

            record.msg = message.replace(self.name, masked_name)
            record.args = ()  # Assign an empty tuple instead of an empty list
        return True


try:
    from rich import print

    from pyicloud.log.httpx import AsyncLogClient as _AsyncLogClient
except ImportError:
    import httpx

    def _AsyncLogClient(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.setdefault("follow_redirects", True)
        return httpx.AsyncClient(**kwargs)


print = print
AsyncLogClient = _AsyncLogClient
