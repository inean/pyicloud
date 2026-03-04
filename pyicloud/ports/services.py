"""Ports for API-facing device, account, and drive service operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol


class DeviceServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates device operations from concrete iCloud service clients
        and provider-specific payload/transport details.

        Implementations map provider responses and action commands into stable
        domain structures consumed by API use-cases and CLI workflows.

    Implemented by: LegacyCoreServicesAdapter
    """

    def list_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        """
        CoreServicesApi calls this method to list devices visible for an authenticated account.

        The adapter translates provider-specific device payloads into stable mappings while
        encapsulating endpoint restoration and transport concerns.

        Raises:
            RuntimeError: Device list cannot be retrieved from upstream services.
        """

    def location(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        """
        CoreServicesApi calls this method to fetch current location data for one device.

        The adapter translates device identity and provider response shape into a domain mapping
        while hiding refresh mechanics and upstream URL details.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Location retrieval fails in provider service.
        """

    def status(self, *, username: str, device_id: str) -> Mapping[str, Any]:
        """
        CoreServicesApi calls this method to fetch status information for one device.

        The adapter translates provider status payloads to stable domain keys and isolates
        service refresh behavior from application orchestration.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Status retrieval fails in provider service.
        """

    def play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        """
        CoreServicesApi calls this method to trigger a play-sound action on one device.

        The adapter translates domain action intent into provider command payloads and handles
        upstream transport details for command delivery.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Upstream device command fails.
        """

    def display_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        """
        CoreServicesApi calls this method to show a message on one device.

        The adapter translates domain message command fields into provider payloads and keeps
        endpoint/serialization concerns out of application logic.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Upstream device command fails.
        """

    def lost_mode(
        self,
        *,
        username: str,
        device_id: str,
        number: str,
        text: str,
        newpasscode: str,
    ) -> None:
        """
        CoreServicesApi calls this method to enable lost mode for one device.

        The adapter translates domain lost-mode command fields into provider-specific request
        payloads and encapsulates remote command execution details.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Upstream device command fails.
        """


class AccountServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates account query operations from concrete service SDK
        classes and transport-layer details.

        Implementations translate provider account payloads into domain mappings
        used by API responses and CLI presentation layers.

    Implemented by: LegacyCoreServicesAdapter
    """

    def account_devices(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        """
        CoreServicesApi calls this method to list account-managed device metadata.

        The adapter translates provider account device objects into stable mappings
        and hides upstream session/endpoint restoration concerns.

        Raises:
            RuntimeError: Account device data cannot be retrieved.
        """

    def account_family(self, *, username: str) -> Sequence[Mapping[str, Any]]:
        """
        CoreServicesApi calls this method to fetch family membership details.

        The adapter translates provider family member objects into domain mappings
        while encapsulating provider-specific property access.

        Raises:
            RuntimeError: Family data cannot be retrieved.
        """

    def account_storage(self, *, username: str) -> Mapping[str, Any]:
        """
        CoreServicesApi calls this method to fetch account storage summary information.

        The adapter translates provider storage objects and nested usage structures
        into a stable domain mapping for API serialization.

        Raises:
            RuntimeError: Storage data cannot be retrieved or normalized.
        """


class DriveServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates drive/file operations from concrete iCloud drive client
        classes and provider-specific path semantics.

        Implementations translate domain path/action intent into provider calls and
        map drive node metadata and content back to stable domain responses.

    Implemented by: LegacyCoreServicesAdapter
    """

    def tree(self, *, username: str, path: str) -> Mapping[str, Any]:
        """
        CoreServicesApi calls this method to list drive node metadata and children for a path.

        The adapter translates domain path intent into provider node traversal and maps node
        details into a stable mapping independent of provider object types.

        Raises:
            KeyError: Path does not resolve to a valid drive node.
            RuntimeError: Drive tree retrieval fails.
        """

    def file_metadata(self, *, username: str, path: str) -> Mapping[str, Any]:
        """
        CoreServicesApi calls this method to fetch metadata for one drive file path.

        The adapter translates provider node objects into stable file metadata mappings and
        keeps provider node typing out of core application logic.

        Raises:
            KeyError: Path does not resolve to a valid file node.
            RuntimeError: File metadata retrieval fails.
        """

    def file_content(self, *, username: str, path: str) -> bytes:
        """
        CoreServicesApi calls this method to read binary content for one drive file path.

        The adapter translates provider download stream behavior into raw bytes and encapsulates
        provider-specific streaming/transport details.

        Raises:
            KeyError: Path does not resolve to a valid file node.
            RuntimeError: File content retrieval fails.
        """

    def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        """
        CoreServicesApi calls this method to create a folder in drive.

        The adapter translates domain folder-creation intent into provider node commands and
        hides drive service mutation payload structure from the application core.

        Raises:
            KeyError: Parent path does not resolve to a valid folder node.
            RuntimeError: Folder creation fails.
        """

    def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        """
        CoreServicesApi calls this method to upload file content to drive.

        The adapter translates domain upload intent into provider upload primitives and manages
        provider-specific file object requirements internally.

        Raises:
            KeyError: Parent path does not resolve to a valid folder node.
            RuntimeError: Upload fails.
        """

    def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        """
        CoreServicesApi calls this method to rename a file or folder node.

        The adapter translates domain rename intent into provider node mutation calls and hides
        provider-specific concurrency/etag handling from the core.

        Raises:
            KeyError: Path does not resolve to a valid node.
            RuntimeError: Rename operation fails.
        """

    def delete_node(self, *, username: str, path: str) -> None:
        """
        CoreServicesApi calls this method to delete a file or folder node.

        The adapter translates domain delete intent into provider trash/remove commands while
        encapsulating provider-specific node lifecycle rules.

        Raises:
            KeyError: Path does not resolve to a valid node.
            RuntimeError: Delete operation fails.
        """
