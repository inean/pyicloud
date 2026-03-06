"""Shared API response helpers."""

from __future__ import annotations

from typing import Any


def ok(payload: Any) -> dict[str, Any]:
    """Wrap successful payloads in the API data envelope."""
    return {"data": payload}
