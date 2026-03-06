"""Compatibility shim for auth API application service moved to auth context."""

from pyicloud.contexts.crosscutting.auth.application.api_auth import AuthApiService, AuthServiceFactory

__all__ = ["AuthApiService", "AuthServiceFactory"]
