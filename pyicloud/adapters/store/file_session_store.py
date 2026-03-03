"""File-backed session store adapter."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from pyicloud.ports import SessionStorePort


class FileSessionStoreAdapter(SessionStorePort):
    """Persist account-scoped session payloads as JSON files."""

    def __init__(self, root_dir: str | os.PathLike[str] | None = None):
        if root_dir is None:
            root_dir = os.getenv("PYICLOUD_SESSION_STORE_DIR", ".cache/pyicloud/sessions")
        self._root = Path(root_dir).expanduser()
        self._root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, account_id: str) -> Path:
        file_name = re.sub(r"\W", "", account_id)
        if not file_name:
            raise RuntimeError("Account id cannot be empty")
        return self._root / f"{file_name}.json"

    def load(self, account_id: str) -> dict[str, Any] | None:
        path = self._path_for(account_id)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as err:
            raise RuntimeError(f"Invalid session store payload: {path}") from err
        if not isinstance(payload, dict):
            raise RuntimeError(f"Invalid session store shape: {path}")
        return payload

    def save(self, account_id: str, payload: dict[str, Any]) -> None:
        path = self._path_for(account_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))

    def clear(self, account_id: str) -> None:
        path = self._path_for(account_id)
        if path.exists():
            path.unlink()
