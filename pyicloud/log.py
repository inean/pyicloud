import inspect
import logging
from venv import logger

LOGGER = logging.getLogger(__name__)


def get_logger(name):
    """Get a logger for the given name."""
    callee = inspect.stack()[3]
    module = inspect.getmodule(callee[0])
    return logging.getLogger(module.__name__).getChild(name)


def log_request(func):
    def wrapper(self, method, url, **kwargs):
        # Charge logging to the right service endpoint
        logger = get_logger("http")
        logger.debug("%s %s %s", method, url, kwargs.get("data", ""))
        return func(self, method, url, logger, **kwargs)

    return wrapper


class PyiCloudPasswordFilter(logging.Filter):
    """Password log hider."""

    _ACTIVE_FILTERS = {}

    @classmethod
    def register(cls, instance, logger=LOGGER):
        """Register the object to the active filters."""
        if logger not in cls._ACTIVE_FILTERS:
            cls._ACTIVE_FILTERS[logger] = {}
        assert instance not in cls._ACTIVE_FILTERS[logger]
        cls._ACTIVE_FILTERS[logger][instance] = None

    @classmethod
    def on_password_changed(cls, value):
        """Update the password for the active filters."""
        for logger in cls._ACTIVE_FILTERS:
            for instance, password_filter in cls._ACTIVE_FILTERS[logger].items():
                if password_filter:
                    logger.removeFilter(password_filter)
                if value:
                    password_filter = cls(value)
                    logger.addFilter(password_filter)
                    cls._ACTIVE_FILTERS[logger][instance] = password_filter

    def __init__(self, password):
        super().__init__(password)

    def filter(self, record):
        message = record.getMessage()
        if self.name in message:
            record.msg = message.replace(self.name, "*" * 8)
            record.args = ()  # Assign an empty tuple instead of an empty list
        return True
