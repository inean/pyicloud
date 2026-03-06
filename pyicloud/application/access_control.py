"""Compatibility shim for access-control service moved to auth context."""

from pyicloud.contexts.crosscutting.auth.application.access_control import AccessControlApiService

__all__ = ["AccessControlApiService"]
