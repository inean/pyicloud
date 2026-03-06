"""Ports for allowlist/admin access-control state used by the API layer."""

from __future__ import annotations

from typing import Protocol

from pyicloud.domain.api_models import AccessControlEntry, AccessRole, AccessStatus


class AccessControlQueryPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates read-only allowlist/admin lookups from API auth and
        admin application services.

        Implementations expose normalized access-control state while the
        application core remains independent from persistence details.

    Implemented by: InMemoryAccessControlStore, FileAccessControlStore
    """

    def get_entry(self, username: str) -> AccessControlEntry | None:
        """
        AuthApiService and AccessControlApiService call this method to load access metadata for one account.

        The adapter translates normalized usernames into stored records and maps persistence payloads into
        AccessControlEntry objects used by application authorization rules.

        Raises:
            RuntimeError: Access-control state cannot be read safely from persistence.
        """

    def list_entries(self) -> tuple[AccessControlEntry, ...]:
        """
        AccessControlApiService calls this method to enumerate allowlist/admin records for management APIs.

        The adapter translates backend-specific list iteration to stable, normalized AccessControlEntry values
        so API orchestration can enforce role/status invariants consistently.

        Raises:
            RuntimeError: Access-control state cannot be enumerated reliably.
        """

    def active_admin_count(self) -> int:
        """
        AccessControlApiService and bootstrap composition call this method to enforce last-admin invariants.

        The adapter translates persisted role/status values into an aggregate count of active admin users
        without leaking storage-specific query behavior into the application layer.

        Raises:
            RuntimeError: Admin count cannot be derived reliably from persistence.
        """


class AccessControlCommandPort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates mutation of allowlist/admin records from API auth and
        admin orchestration services.

        Implementations persist normalized role/status transitions, version bumps,
        and metadata updates required for stale-token invalidation.

    Implemented by: InMemoryAccessControlStore, FileAccessControlStore
    """

    def upsert_entry(
        self,
        *,
        username: str,
        roles: tuple[AccessRole, ...],
        status: AccessStatus,
        actor: str,
    ) -> AccessControlEntry:
        """
        AccessControlApiService and bootstrap composition call this method to create or update allowlist records.

        The adapter translates domain role/status transitions into persisted records, updates audit metadata, and
        increments ACL version so existing bearer tokens can be invalidated when ACL state changes.

        Raises:
            RuntimeError: Access-control state cannot be persisted reliably.
        """

    def delete_entry(self, *, username: str, actor: str) -> bool:
        """
        AccessControlApiService calls this method to remove an allowlist/admin record by username.

        The adapter translates domain deletion intent into backend-specific record removal and reports whether
        any record existed, while keeping storage semantics outside the application core.

        Raises:
            RuntimeError: Access-control state cannot be mutated safely.
        """
