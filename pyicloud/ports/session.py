"""Ports for API token signing and auth challenge/session state management."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class TokenSignerPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates bearer token signing and verification from API
        application services that orchestrate authentication decisions.

        Implementations encapsulate cryptographic details so token format
        changes remain outside the application core.

    Implemented by: JwtTokenSigner
    """

    def sign(self, *, subject: str, claims: Mapping[str, Any], expires_in_seconds: int) -> str:
        """
        AuthApiService calls this method to create a bearer token for an authenticated user.

        The adapter translates domain claims into a concrete token payload and signs it with
        external crypto libraries without leaking algorithm details to the core.

        Raises:
            RuntimeError: Token signing fails due to invalid payload or signer state.
        """

    def verify(self, token: str) -> Mapping[str, Any]:
        """
        AuthApiService calls this method to validate and decode bearer tokens from API clients.

        The adapter translates token parsing and signature/expiry checks into domain claims that
        application services consume for authorization decisions.

        Raises:
            RuntimeError: Token is invalid, expired, or cannot be decoded.
        """


class SessionQueryPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates read-only lookup of auth challenges and revoked-token
        state from API application orchestration.

        Implementations provide query access to session/challenge persistence while
        the core stays independent from storage and TTL details.

    Implemented by: InMemoryApiSessionStore
    """

    def get_challenge(self, challenge_id: str) -> Mapping[str, Any] | None:
        """
        AuthApiService calls this method to fetch pending 2FA challenge context.

        The adapter translates challenge identifiers to stored payloads and hides
        storage-specific expiry checks and cleanup behavior.

        Raises:
            RuntimeError: Challenge state cannot be read safely from persistence.
        """

    def is_token_revoked(self, token_id: str) -> bool:
        """
        AuthApiService calls this method to determine whether a bearer token is revoked.

        The adapter translates token identifiers to revocation state while keeping
        persistence lookups and TTL logic outside the core application service.

        Raises:
            RuntimeError: Revocation state cannot be queried reliably.
        """


class SessionCommandPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates mutation of auth challenge and token revocation state
        from API use-case orchestration.

        Implementations persist and expire mutable auth/session artifacts while
        the core remains independent from concrete storage backends.

    Implemented by: InMemoryApiSessionStore
    """

    def put_challenge(self, *, challenge_id: str, payload: Mapping[str, Any], ttl_seconds: int) -> None:
        """
        AuthApiService calls this method to store pending challenge context after login step one.

        The adapter translates domain challenge payloads into persistence records and applies
        backend-specific expiration behavior for challenge lifetimes.

        Raises:
            RuntimeError: Challenge state cannot be persisted reliably.
        """

    def delete_challenge(self, challenge_id: str) -> None:
        """
        AuthApiService calls this method to clear challenge state after completion or failure.

        The adapter translates challenge lifecycle events into storage deletion operations and
        hides backend-specific record management from the application service.

        Raises:
            RuntimeError: Challenge state cannot be deleted reliably.
        """

    def revoke_token(self, *, token_id: str, ttl_seconds: int) -> None:
        """
        AuthApiService calls this method to mark a token revoked during logout.

        The adapter translates token lifecycle intent into revocation persistence and applies
        expiration rules so revocation state does not outlive token validity.

        Raises:
            RuntimeError: Token revocation state cannot be persisted reliably.
        """
