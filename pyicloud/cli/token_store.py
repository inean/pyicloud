"""Token persistence helpers for the API-driven CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_TOKEN_FILE = ".cache/pyicloud/api/token.json"
TOKEN_FILE_ENV = "PYICLOUD_API_TOKEN_FILE"


def token_file() -> Path:
    raw = os.getenv(TOKEN_FILE_ENV, DEFAULT_TOKEN_FILE)
    return Path(raw).expanduser()


def load_token(*, path: Path | None = None) -> str | None:
    token_path = path or token_file()
    if not token_path.exists():
        return None
    try:
        payload = json.loads(token_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    token = payload.get("access_token")
    return str(token) if token else None


def save_token(token: str, *, path: Path | None = None) -> None:
    token_path = path or token_file()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(
        json.dumps({"access_token": token}, separators=(",", ":")),
        encoding="utf-8",
    )


def clear_token(*, path: Path | None = None) -> None:
    token_path = path or token_file()
    if token_path.exists():
        token_path.unlink()
