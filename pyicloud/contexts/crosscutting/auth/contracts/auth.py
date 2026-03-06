"""Auth/session and service ports for the new application layer."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class AuthSessionPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates auth/session orchestration from concrete iCloud tree
        and transport implementations.

        The application layer coordinates signin, challenge completion, trust,
        account login, and validation while adapters handle protocol details.

    Implemented by: TreeAuthSessionAdapter, FakeAuthSessionAdapter
    """

    async def signin(self, *, refresh_signin: bool) -> bool:
        """
        AuthSessionService calls this method to start a signin attempt.

        The adapter translates domain-level signin intent into concrete tree
        actions and returns whether a 2FA code is required.

        Raises:
            SecurityCodeRequired: The upstream challenge requires a 2FA step.
            RuntimeError: Upstream signin could not complete.
        """

    async def security_code(self, code: str) -> None:
        """
        AuthSessionService calls this method to complete a 2FA challenge.

        The adapter translates the provided code into the upstream security-code
        payload and maps provider errors to domain-level failures.

        Raises:
            SecurityCodeRequired: The provided code is invalid or expired.
            RuntimeError: Upstream challenge submission failed.
        """

    async def trust(self) -> None:
        """
        AuthSessionService calls this method to request a trusted session.

        The adapter maps trust-token interaction with upstream APIs and keeps
        trust state outside the application core.

        Raises:
            SecurityCodeRequired: Trust requires a completed challenge first.
            RuntimeError: Upstream trust request failed.
        """

    async def account_login(self, *, require_trust_token: bool) -> None:
        """
        AuthSessionService calls this method to fetch account login context.

        The adapter translates trust requirements and upstream account login
        payloads into a stable domain-facing completion signal.

        Raises:
            SecurityCodeRequired: A trust token is required but unavailable.
            RuntimeError: Upstream account login request failed.
        """

    async def session_validate(self) -> Mapping[str, Any]:
        """
        AuthSessionService calls this method to validate/renew current session state.

        The adapter maps upstream validate responses into a domain-facing API
        payload dictionary consumed by subsequent service use-cases.

        Raises:
            SecurityCodeRequired: Session validation requires a fresh challenge.
            RuntimeError: Upstream session validation failed.
        """


class SessionStorePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates persistence concerns for account-scoped auth/session
        state from application flow logic.

        Adapters provide durable storage and retrieval while the core remains
        agnostic to filesystem layout and serialization details.

    Implemented by: FileSessionStoreAdapter, InMemorySessionStoreAdapter
    """

    def load(self, account_id: str) -> Mapping[str, Any] | None:
        """
        AuthSessionService calls this method to restore prior session state.

        The adapter translates persisted records into a domain-facing mapping
        and hides storage-specific shape and deserialization details.

        Raises:
            RuntimeError: Persisted state cannot be loaded safely.
        """

    def save(self, account_id: str, payload: Mapping[str, Any]) -> None:
        """
        AuthSessionService calls this method to persist updated session state.

        The adapter translates domain payload data into storage records and
        enforces account isolation in its persistence backend.

        Raises:
            RuntimeError: State cannot be persisted reliably.
        """

    def clear(self, account_id: str) -> None:
        """
        AuthSessionService calls this method to remove stale or invalid state.

        The adapter translates account-level clear intent into storage-specific
        deletion logic while preserving domain isolation guarantees.

        Raises:
            RuntimeError: Stored state cannot be removed reliably.
        """


class ServiceEndpointPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates restoration of service endpoints from persisted
        auth/session payloads and local settings/cookies state.

        Adapters map stored payloads plus local transport/session details into
        endpoint objects consumable by runtime service clients.

    Implemented by: LegacyServiceEndpointFactoryAdapter
    """

    def from_payload(self, *, username: str, password: str, payload: Mapping[str, Any]) -> Any:
        """
        ServiceEndpointRestoreService calls this method to rebuild a runtime endpoint.

        The adapter translates persisted auth payloads and local session/config files
        into an endpoint object while hiding transport-specific wiring details.

        Raises:
            RuntimeError: Endpoint restoration fails due to invalid local/session data.
            ValueError: Payload does not contain required service endpoint structure.
        """
