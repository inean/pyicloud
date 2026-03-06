"""Ports for API-facing service operations."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from pyicloud.domain import (
    AccountDeviceDTO,
    AccountFamilyMemberDTO,
    AccountStorageDTO,
    CalendarDTO,
    CalendarEventDetailDTO,
    CalendarEventDTO,
    ContactDTO,
    DeviceRecordDTO,
    DriveNodeDTO,
    PhotoAlbumDTO,
    PhotoAssetDTO,
    ReminderListsDTO,
    UbiquityNodeDTO,
)


class DeviceServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates device operations from concrete iCloud service clients
        and provider-specific payload/transport details.

        Implementations map provider responses and action commands into stable
        domain structures consumed by API use-cases and CLI workflows.

    Implemented by: DevicesServiceAdapter, LegacyCoreServicesAdapter
    """

    async def list_devices(self, *, username: str) -> Sequence[DeviceRecordDTO]:
        """
        CoreServicesApi calls this method to list devices visible for an authenticated account.

        The adapter translates provider-specific device payloads into stable mappings while
        encapsulating endpoint restoration and transport concerns.

        Raises:
            RuntimeError: Device list cannot be retrieved from upstream services.
        """

    async def location(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        """
        CoreServicesApi calls this method to fetch current location data for one device.

        The adapter translates device identity and provider response shape into a domain mapping
        while hiding refresh mechanics and upstream URL details.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Location retrieval fails in provider service.
        """

    async def status(self, *, username: str, device_id: str) -> DeviceRecordDTO:
        """
        CoreServicesApi calls this method to fetch status information for one device.

        The adapter translates provider status payloads to stable domain keys and isolates
        service refresh behavior from application orchestration.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Status retrieval fails in provider service.
        """

    async def play_sound(self, *, username: str, device_id: str, subject: str) -> None:
        """
        CoreServicesApi calls this method to trigger a play-sound action on one device.

        The adapter translates domain action intent into provider command payloads and handles
        upstream transport details for command delivery.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Upstream device command fails.
        """

    async def display_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool) -> None:
        """
        CoreServicesApi calls this method to show a message on one device.

        The adapter translates domain message command fields into provider payloads and keeps
        endpoint/serialization concerns out of application logic.

        Raises:
            KeyError: Device identifier is unknown for the authenticated account.
            RuntimeError: Upstream device command fails.
        """

    async def lost_mode(
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

    Implemented by: AccountServiceAdapter, LegacyCoreServicesAdapter
    """

    async def account_devices(self, *, username: str) -> Sequence[AccountDeviceDTO]:
        """
        CoreServicesApi calls this method to list account-managed device metadata.

        The adapter translates provider account device objects into stable mappings
        and hides upstream session/endpoint restoration concerns.

        Raises:
            RuntimeError: Account device data cannot be retrieved.
        """

    async def account_family(self, *, username: str) -> Sequence[AccountFamilyMemberDTO]:
        """
        CoreServicesApi calls this method to fetch family membership details.

        The adapter translates provider family member objects into domain mappings
        while encapsulating provider-specific property access.

        Raises:
            RuntimeError: Family data cannot be retrieved.
        """

    async def account_storage(self, *, username: str) -> AccountStorageDTO:
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

    Implemented by: DriveServiceAdapter, LegacyCoreServicesAdapter
    """

    async def tree(self, *, username: str, path: str) -> DriveNodeDTO:
        """
        CoreServicesApi calls this method to list drive node metadata and children for a path.

        The adapter translates domain path intent into provider node traversal and maps node
        details into a stable mapping independent of provider object types.

        Raises:
            KeyError: Path does not resolve to a valid drive node.
            RuntimeError: Drive tree retrieval fails.
        """

    async def file_metadata(self, *, username: str, path: str) -> DriveNodeDTO:
        """
        CoreServicesApi calls this method to fetch metadata for one drive file path.

        The adapter translates provider node objects into stable file metadata mappings and
        keeps provider node typing out of core application logic.

        Raises:
            KeyError: Path does not resolve to a valid file node.
            RuntimeError: File metadata retrieval fails.
        """

    async def file_content(self, *, username: str, path: str) -> bytes:
        """
        CoreServicesApi calls this method to read binary content for one drive file path.

        The adapter translates provider download stream behavior into raw bytes and encapsulates
        provider-specific streaming/transport details.

        Raises:
            KeyError: Path does not resolve to a valid file node.
            RuntimeError: File content retrieval fails.
        """

    async def create_folder(self, *, username: str, parent_path: str, name: str) -> None:
        """
        CoreServicesApi calls this method to create a folder in drive.

        The adapter translates domain folder-creation intent into provider node commands and
        hides drive service mutation payload structure from the application core.

        Raises:
            KeyError: Parent path does not resolve to a valid folder node.
            RuntimeError: Folder creation fails.
        """

    async def upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes) -> None:
        """
        CoreServicesApi calls this method to upload file content to drive.

        The adapter translates domain upload intent into provider upload primitives and manages
        provider-specific file object requirements internally.

        Raises:
            KeyError: Parent path does not resolve to a valid folder node.
            RuntimeError: Upload fails.
        """

    async def rename_node(self, *, username: str, path: str, new_name: str) -> None:
        """
        CoreServicesApi calls this method to rename a file or folder node.

        The adapter translates domain rename intent into provider node mutation calls and hides
        provider-specific concurrency/etag handling from the core.

        Raises:
            KeyError: Path does not resolve to a valid node.
            RuntimeError: Rename operation fails.
        """

    async def delete_node(self, *, username: str, path: str) -> None:
        """
        CoreServicesApi calls this method to delete a file or folder node.

        The adapter translates domain delete intent into provider trash/remove commands while
        encapsulating provider-specific node lifecycle rules.

        Raises:
            KeyError: Path does not resolve to a valid node.
            RuntimeError: Delete operation fails.
        """


class CalendarServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates calendar query operations from concrete iCloud
        calendar clients and upstream payload formats.

        Implementations map provider calendar/event payloads into stable
        structures that API and CLI layers can present consistently.

    Implemented by: CalendarServiceAdapter, LegacyCoreServicesAdapter
    """

    async def calendars(self, *, username: str) -> Sequence[CalendarDTO]:
        """
        CoreServicesApi calls this method to list available calendars for an account.

        The adapter translates provider collection payloads into stable mappings and
        hides endpoint/session setup details from application orchestration.

        Raises:
            RuntimeError: Calendar collection data cannot be retrieved.
        """

    async def events(
        self,
        *,
        username: str,
        from_dt: datetime | None = None,
        to_dt: datetime | None = None,
    ) -> Sequence[CalendarEventDTO]:
        """
        CoreServicesApi calls this method to fetch calendar events in a date window.

        The adapter translates domain date-range intent into provider query parameters
        and normalizes provider event payloads into domain-level mappings.

        Raises:
            RuntimeError: Event data cannot be retrieved.
        """

    async def event_detail(self, *, username: str, calendar_guid: str, event_guid: str) -> CalendarEventDetailDTO:
        """
        CoreServicesApi calls this method to fetch one calendar event detail payload.

        The adapter translates domain event identity fields into provider requests and
        returns a stable mapping independent of provider response wrappers.

        Raises:
            KeyError: Event or calendar identifiers are unknown.
            RuntimeError: Event detail retrieval fails.
        """


class ContactsServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates contacts queries from concrete iCloud contacts clients
        and provider-specific pagination or token mechanics.

        Implementations map provider contact payloads into stable domain mappings
        consumed by API responses and CLI output.

    Implemented by: ContactsServiceAdapter, LegacyCoreServicesAdapter
    """

    async def all_contacts(self, *, username: str) -> Sequence[ContactDTO]:
        """
        CoreServicesApi calls this method to fetch all contacts for an account.

        The adapter translates provider contacts payloads and sync flows into domain
        mappings while keeping provider tokens and endpoint sequencing internal.

        Raises:
            RuntimeError: Contact data cannot be retrieved.
        """


class RemindersServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates reminders operations from concrete iCloud reminders
        clients and provider request payload schemas.

        Implementations map reminder list/create intents to provider calls and
        normalize provider responses into stable domain structures.

    Implemented by: RemindersServiceAdapter, LegacyCoreServicesAdapter
    """

    async def reminder_lists(self, *, username: str) -> ReminderListsDTO:
        """
        CoreServicesApi calls this method to fetch reminders grouped by list title.

        The adapter translates provider reminder collection payloads into domain
        list mappings and encapsulates provider refresh behaviors.

        Raises:
            RuntimeError: Reminder list data cannot be retrieved.
        """

    async def create_reminder(
        self,
        *,
        username: str,
        title: str,
        description: str = "",
        collection: str | None = None,
        due_date: datetime | None = None,
    ) -> bool:
        """
        CoreServicesApi calls this method to create a reminder in the selected list.

        The adapter translates domain reminder fields into provider mutation payloads
        and maps provider success/failure status to a domain-level boolean result.

        Raises:
            RuntimeError: Reminder creation fails in provider service.
        """


class PhotosServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates photo library operations from concrete iCloud photos
        clients and provider-specific album/asset pagination details.

        Implementations map domain photo library queries to provider calls and
        normalize album, asset metadata, and binary content to stable outputs.

    Implemented by: PhotosServiceAdapter, LegacyCoreServicesAdapter
    """

    async def list_albums(self, *, username: str) -> Sequence[PhotoAlbumDTO]:
        """
        CoreServicesApi calls this method to list available photo albums for an account.

        The adapter translates provider album objects into stable mappings and hides
        provider-specific lazy-loading and count lookup behavior from the core.

        Raises:
            RuntimeError: Album data cannot be retrieved.
        """

    async def list_assets(
        self,
        *,
        username: str,
        album: str = "All Photos",
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[PhotoAssetDTO]:
        """
        CoreServicesApi calls this method to list photo assets from one album window.

        The adapter translates domain pagination and album selection into provider
        iteration behavior and returns stable asset metadata mappings.

        Raises:
            KeyError: Album name is unknown.
            RuntimeError: Asset listing fails.
        """

    async def asset_metadata(self, *, username: str, asset_id: str, album: str = "All Photos") -> PhotoAssetDTO:
        """
        CoreServicesApi calls this method to fetch metadata for one photo asset.

        The adapter translates domain asset identity into provider asset lookup and
        returns normalized metadata independent of provider record structure.

        Raises:
            KeyError: Album or asset identifier is unknown.
            RuntimeError: Asset metadata retrieval fails.
        """

    async def asset_content(
        self,
        *,
        username: str,
        asset_id: str,
        album: str = "All Photos",
        version: str = "original",
    ) -> bytes:
        """
        CoreServicesApi calls this method to fetch binary bytes for one photo asset version.

        The adapter translates domain version selection to provider download calls and
        converts provider streaming responses into raw bytes for API transport.

        Raises:
            KeyError: Album, asset, or version is unknown.
            RuntimeError: Asset download fails.
        """


class UbiquityServicePort(Protocol):
    """
    Direction: outbound

    Purpose:
        This port isolates ubiquity file-library reads from concrete iCloud
        ubiquity clients and provider-specific node traversal mechanics.

        Implementations map domain path reads to provider node lookups and
        normalize node metadata and file bytes to stable API outputs.

    Implemented by: UbiquityServiceAdapter, LegacyCoreServicesAdapter
    """

    async def ubiquity_tree(self, *, username: str, path: str) -> UbiquityNodeDTO:
        """
        CoreServicesApi calls this method to list ubiquity node metadata and children for a path.

        The adapter translates domain path intent into provider node traversal and
        maps node trees into stable mappings for API and CLI usage.

        Raises:
            KeyError: Path does not resolve to a valid ubiquity node.
            RuntimeError: Tree retrieval fails.
        """

    async def ubiquity_file_metadata(self, *, username: str, path: str) -> UbiquityNodeDTO:
        """
        CoreServicesApi calls this method to fetch metadata for one ubiquity node path.

        The adapter translates provider node objects into stable metadata mappings and
        hides provider-specific datetime parsing and node typing concerns.

        Raises:
            KeyError: Path does not resolve to a valid ubiquity node.
            RuntimeError: Metadata retrieval fails.
        """

    async def ubiquity_file_content(self, *, username: str, path: str) -> bytes:
        """
        CoreServicesApi calls this method to fetch binary content for one ubiquity file path.

        The adapter translates provider file download behavior into raw bytes and
        encapsulates provider-specific streaming or buffering semantics.

        Raises:
            KeyError: Path does not resolve to a valid file node.
            RuntimeError: File content retrieval fails.
        """
