"""Domain models used by API authentication services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """Authenticated principal recovered from bearer token claims."""

    username: str
    token_id: str
    expires_at: int
