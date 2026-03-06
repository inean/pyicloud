"""Compatibility shim for observability API moved to observability context."""

from pyicloud.contexts.crosscutting.observability.application.observability import ObservabilityApi

__all__ = ["ObservabilityApi"]
