"""Compatibility shim for console HTTP telemetry adapter."""

from pyicloud.contexts.crosscutting.telemetry.adapters.console_http import (
    AsyncConsoleLogTransport as AsyncLogTransport,
)
from pyicloud.contexts.crosscutting.telemetry.adapters.console_http import (
    ConsoleLogTransport as LogTransport,
)
from pyicloud.contexts.crosscutting.telemetry.adapters.console_http import (
    ConsoleTelemetryHook as LoggerHook,
)

__all__ = ["AsyncLogTransport", "LoggerHook", "LogTransport"]
