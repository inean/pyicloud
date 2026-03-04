"""Domain-level errors for API authentication and authorization workflows."""

from __future__ import annotations


class ApiDomainError(Exception):
    """Base domain error for API-facing orchestration."""


class InvalidCredentials(ApiDomainError):
    """Raised when username/password authentication is rejected."""


class ChallengeRequired(ApiDomainError):
    """Raised when a second authentication step is required."""


class InvalidSecurityCode(ApiDomainError):
    """Raised when a submitted 2FA security code is invalid."""


class ChallengeExpired(ApiDomainError):
    """Raised when a challenge identifier is unknown or expired."""


class Unauthorized(ApiDomainError):
    """Raised when bearer token validation fails."""
