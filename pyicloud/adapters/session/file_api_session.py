"""File-backed implementation for API challenge and token-revocation state."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from time import time
from typing import Any

from pyicloud.ports import SessionCommandPort, SessionQueryPort


class FileApiSessionStore(SessionQueryPort, SessionCommandPort):
    """Persist challenge and revocation state as JSON for multi-process durability."""

    def __init__(
        self,
        *,
        root_dir: str | os.PathLike[str] | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if root_dir is None:
            root_dir = os.getenv("PYICLOUD_API_SESSION_STORE_DIR", ".cache/pyicloud/api-session")
        self._root = Path(root_dir).expanduser()
        self._root.mkdir(parents=True, exist_ok=True)
        self._path = self._root / "auth_state.json"
        self._clock = clock or time

    @staticmethod
    def _empty_state() -> dict[str, dict[str, Any]]:
        return {"challenges": {}, "revoked": {}}

    def _read_state(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return self._empty_state()
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise RuntimeError(f"Invalid API auth state payload: {self._path}") from err
        if not isinstance(payload, dict):
            raise RuntimeError(f"Invalid API auth state shape: {self._path}")
        challenges = payload.get("challenges")
        revoked = payload.get("revoked")
        if not isinstance(challenges, dict) or not isinstance(revoked, dict):
            raise RuntimeError(f"Invalid API auth state shape: {self._path}")
        return {"challenges": dict(challenges), "revoked": dict(revoked)}

    def _write_state(self, state: Mapping[str, Mapping[str, Any]]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(state, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp_path.replace(self._path)

    def _cleanup_state(self, state: dict[str, dict[str, Any]]) -> bool:
        changed = False
        now = self._clock()

        for challenge_id, record in list(state["challenges"].items()):
            if not isinstance(record, dict):
                state["challenges"].pop(challenge_id, None)
                changed = True
                continue
            expires_at = float(record.get("expires_at", 0))
            if expires_at <= now:
                state["challenges"].pop(challenge_id, None)
                changed = True

        for token_id, expires_at in list(state["revoked"].items()):
            try:
                expires_value = float(expires_at)
            except (TypeError, ValueError):
                state["revoked"].pop(token_id, None)
                changed = True
                continue
            if expires_value <= now:
                state["revoked"].pop(token_id, None)
                changed = True

        return changed

    def get_challenge(self, challenge_id: str) -> Mapping[str, Any] | None:
        state = self._read_state()
        if self._cleanup_state(state):
            self._write_state(state)
        record = state["challenges"].get(challenge_id)
        if not isinstance(record, dict):
            return None
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return None
        return dict(payload)

    def is_token_revoked(self, token_id: str) -> bool:
        state = self._read_state()
        if self._cleanup_state(state):
            self._write_state(state)
        return token_id in state["revoked"]

    def put_challenge(self, *, challenge_id: str, payload: Mapping[str, Any], ttl_seconds: int) -> None:
        state = self._read_state()
        self._cleanup_state(state)
        state["challenges"][challenge_id] = {
            "expires_at": self._clock() + ttl_seconds,
            "payload": dict(payload),
        }
        self._write_state(state)

    def delete_challenge(self, challenge_id: str) -> None:
        state = self._read_state()
        self._cleanup_state(state)
        state["challenges"].pop(challenge_id, None)
        self._write_state(state)

    def revoke_token(self, *, token_id: str, ttl_seconds: int) -> None:
        state = self._read_state()
        self._cleanup_state(state)
        state["revoked"][token_id] = self._clock() + ttl_seconds
        self._write_state(state)
