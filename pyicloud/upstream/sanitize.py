"""Redaction helpers for upstream request/response telemetry payloads."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from http.cookies import SimpleCookie
from typing import Any

_SENSITIVE_NAME = re.compile(
    r"(?:pass|password|secret|token|session|cookie|authorization|auth|scnt|code|trust)",
    re.IGNORECASE,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redacted_scalar(value: str | bytes | bytearray | None) -> dict[str, Any]:
    """Return metadata-only representation of sensitive values."""
    if value is None:
        return {"present": False, "length": 0, "sha256": ""}
    if isinstance(value, bytes | bytearray):
        raw = bytes(value)
        return {
            "present": True,
            "length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    text = str(value)
    return {
        "present": True,
        "length": len(text),
        "sha256": _digest(text),
    }


def _is_sensitive_name(name: str) -> bool:
    return bool(_SENSITIVE_NAME.search(name))


def sanitize_headers(headers: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Sanitize headers and cookies from an HTTP message."""
    clean_headers: dict[str, Any] = {}
    clean_cookies: dict[str, Any] = {}

    for raw_key, raw_value in headers.items():
        key = raw_key.lower()
        value = str(raw_value)

        if key in {"cookie", "set-cookie"}:
            cookies = SimpleCookie()
            parts = value.split(", ") if key == "set-cookie" else [value]
            for cookie_str in parts:
                cookies.load(cookie_str)
            for cookie_name, morsel in cookies.items():
                clean_cookies[cookie_name] = redacted_scalar(morsel.value)
            clean_headers[key] = {"present": True, "count": len(clean_cookies)}
            continue

        if _is_sensitive_name(key):
            clean_headers[key] = redacted_scalar(value)
            continue

        if len(value) > 512:
            clean_headers[key] = {
                "text": value[:512],
                "truncated": True,
                "length": len(value),
            }
            continue

        clean_headers[key] = value

    return clean_headers, clean_cookies


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, raw in value.items():
            if _is_sensitive_name(str(key)):
                sanitized[str(key)] = redacted_scalar(str(raw))
            else:
                sanitized[str(key)] = _sanitize_json(raw)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, str) and len(value) > 2048:
        return {"text": value[:2048], "truncated": True, "length": len(value)}
    return value


def sanitize_body(
    *,
    body: bytes | bytearray | str | None,
    content_type: str | None,
    max_bytes: int,
) -> tuple[Any, int]:
    """Sanitize one HTTP body while preserving enough detail for inspection."""
    if body is None:
        return None, 0

    if isinstance(body, str):
        raw = body.encode("utf-8")
    else:
        raw = bytes(body)

    size = len(raw)
    truncated = size > max_bytes
    sample = raw[:max_bytes]
    media_type = (content_type or "").split(";")[0].strip().lower()

    if media_type.startswith("application/json"):
        try:
            parsed = json.loads(sample.decode("utf-8", errors="replace"))
            payload: Any = _sanitize_json(parsed)
        except Exception:  # noqa: BLE001
            payload = {
                "text": sample.decode("utf-8", errors="replace"),
                "truncated": truncated,
                "length": size,
            }
        if isinstance(payload, dict):
            payload.setdefault("truncated", truncated)
            payload.setdefault("length", size)
        return payload, size

    if media_type.startswith("text/") or media_type in {
        "application/x-www-form-urlencoded",
        "application/xml",
        "application/javascript",
        "",
    }:
        text = sample.decode("utf-8", errors="replace")
        if _is_sensitive_name(text):
            return redacted_scalar(text), size
        return {
            "text": text,
            "truncated": truncated,
            "length": size,
        }, size

    return {
        "binary": True,
        "mime": media_type or "application/octet-stream",
        "length": size,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": truncated,
    }, size
