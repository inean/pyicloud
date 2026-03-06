"""Compatibility shim for auth-session service moved to auth context."""

from pyicloud.contexts.crosscutting.auth.application.auth_session import AuthSessionService

__all__ = ["AuthSessionService"]
