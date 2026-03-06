"""Compatibility shim for auth abuse-guard service moved to auth context."""

from pyicloud.contexts.crosscutting.auth.application.auth_abuse_guard import AuthAbuseGuardService

__all__ = ["AuthAbuseGuardService"]
