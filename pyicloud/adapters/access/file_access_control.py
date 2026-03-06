"""File-backed implementation for allowlist/admin access-control state."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from time import time
from typing import Any

from pyicloud.adapters.access.in_memory_access_control import _normalize_roles, _normalize_status, _normalize_username
from pyicloud.domain.api_models import AccessControlEntry, AccessRole, AccessStatus
from pyicloud.ports import AccessControlCommandPort, AccessControlQueryPort


class FileAccessControlStore(AccessControlQueryPort, AccessControlCommandPort):
    """Persist allowlist/admin records as JSON for multi-process durability."""

    def __init__(
        self,
        *,
        root_dir: str | os.PathLike[str] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if root_dir is None:
            root_dir = os.getenv("PYICLOUD_API_ACL_STORE_DIR", ".cache/pyicloud/access-control")
        self._root = Path(root_dir).expanduser()
        self._root.mkdir(parents=True, exist_ok=True)
        self._path = self._root / "allowlist.json"
        self._clock = clock or time

    @staticmethod
    def _empty_state() -> dict[str, dict[str, Any]]:
        return {"entries": {}}

    @staticmethod
    def _record_to_entry(record: Mapping[str, Any]) -> AccessControlEntry:
        username = _normalize_username(str(record.get("username", "")))
        roles = _normalize_roles(tuple(record.get("roles", ())))
        status = _normalize_status(str(record.get("status", "")))
        created_by = _normalize_username(str(record.get("created_by", "")))
        try:
            acl_version = int(record.get("acl_version", 0))
            created_at = int(record.get("created_at", 0))
            updated_at = int(record.get("updated_at", 0))
        except (TypeError, ValueError) as err:
            raise RuntimeError("Invalid allowlist metadata values") from err
        if acl_version <= 0:
            raise RuntimeError("Invalid acl_version in allowlist record")
        return AccessControlEntry(
            username=username,
            roles=roles,
            status=status,
            acl_version=acl_version,
            created_by=created_by,
            created_at=created_at,
            updated_at=updated_at,
        )

    @staticmethod
    def _entry_to_record(entry: AccessControlEntry) -> dict[str, Any]:
        return {
            "username": entry.username,
            "roles": list(entry.roles),
            "status": entry.status,
            "acl_version": entry.acl_version,
            "created_by": entry.created_by,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }

    def _read_state(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return self._empty_state()
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise RuntimeError(f"Invalid allowlist payload: {self._path}") from err
        if not isinstance(payload, dict):
            raise RuntimeError(f"Invalid allowlist payload shape: {self._path}")
        entries = payload.get("entries")
        if not isinstance(entries, dict):
            raise RuntimeError(f"Invalid allowlist payload shape: {self._path}")
        return {"entries": dict(entries)}

    def _write_state(self, state: Mapping[str, Mapping[str, Any]]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(state, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(self._path)

    def _load_entries(self) -> dict[str, AccessControlEntry]:
        state = self._read_state()
        loaded: dict[str, AccessControlEntry] = {}
        for username, raw in state["entries"].items():
            if not isinstance(raw, dict):
                raise RuntimeError("Invalid allowlist entry shape")
            entry = self._record_to_entry(raw)
            normalized_key = _normalize_username(username)
            if normalized_key != entry.username:
                raise RuntimeError("Allowlist entry username mismatch")
            loaded[normalized_key] = entry
        return loaded

    def _store_entries(self, entries: Mapping[str, AccessControlEntry]) -> None:
        payload = {"entries": {username: self._entry_to_record(entry) for username, entry in entries.items()}}
        self._write_state(payload)

    def get_entry(self, username: str) -> AccessControlEntry | None:
        normalized_username = _normalize_username(username)
        entries = self._load_entries()
        return entries.get(normalized_username)

    def list_entries(self) -> tuple[AccessControlEntry, ...]:
        entries = self._load_entries()
        ordered = sorted(entries.values(), key=lambda entry: entry.username)
        return tuple(ordered)

    def active_admin_count(self) -> int:
        entries = self._load_entries()
        return sum(1 for entry in entries.values() if entry.status == "active" and "admin" in entry.roles)

    def upsert_entry(
        self,
        *,
        username: str,
        roles: tuple[AccessRole, ...],
        status: AccessStatus,
        actor: str,
    ) -> AccessControlEntry:
        normalized_username = _normalize_username(username)
        normalized_roles = _normalize_roles(roles)
        normalized_status = _normalize_status(status)
        normalized_actor = _normalize_username(actor)

        entries = self._load_entries()
        existing = entries.get(normalized_username)
        now = int(self._clock())
        if existing is not None:
            if existing.roles == normalized_roles and existing.status == normalized_status:
                return existing
            next_entry = AccessControlEntry(
                username=normalized_username,
                roles=normalized_roles,
                status=normalized_status,
                acl_version=existing.acl_version + 1,
                created_by=existing.created_by,
                created_at=existing.created_at,
                updated_at=now,
            )
        else:
            next_entry = AccessControlEntry(
                username=normalized_username,
                roles=normalized_roles,
                status=normalized_status,
                acl_version=1,
                created_by=normalized_actor,
                created_at=now,
                updated_at=now,
            )
        entries[normalized_username] = next_entry
        self._store_entries(entries)
        return next_entry

    def delete_entry(self, *, username: str, actor: str) -> bool:
        _ = _normalize_username(actor)
        normalized_username = _normalize_username(username)
        entries = self._load_entries()
        existed = entries.pop(normalized_username, None) is not None
        if existed:
            self._store_entries(entries)
        return existed
