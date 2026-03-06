"""Optional console adapter for HTTP request/response telemetry."""

from __future__ import annotations

import os
import re
from http.cookies import SimpleCookie
from json import JSONDecodeError
from typing import Any, cast

import httpx

from pyicloud.log import hide_sensitive_data


def _parse_bool_env(name: str, *, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def console_http_telemetry_enabled() -> bool:
    """Return whether console HTTP telemetry is enabled."""
    return _parse_bool_env("PYICLOUD_HTTP_CONSOLE_TELEMETRY", default=False)


class ConsoleTelemetryHook:
    """Pretty console request/response renderer for debugging sessions."""

    styles = {
        "table": {
            "title_justify": "left",
            "width": 100,
        },
        "panel": {
            "title_align": "left",
            "width": 100,
        },
    }

    h_ = staticmethod(lambda value: hide_sensitive_data(value))  # noqa: E731

    @staticmethod
    def _load_rich() -> tuple[Any, Any, Any, Any, Any] | None:
        try:
            from rich import box
            from rich import print as rich_print
            from rich.json import JSON
            from rich.panel import Panel
            from rich.table import Table
        except Exception:  # noqa: BLE001 - this adapter is optional at runtime.
            return None
        return rich_print, JSON, Panel, Table, box

    def parse_headers(self, data: httpx.Response | httpx.Request):
        rich = self._load_rich()
        if rich is None:
            return
        rich_print, _, _, Table, box = rich
        table = Table(**self.styles["table"], box=box.ROUNDED)
        table.add_column("Header", style="gold3", width=30)
        table.add_column("Value")
        for key, value in ((k, v) for k, v in data.headers.items() if not k.lower().endswith("cookie")):
            table.add_row(key, self.h_(value))
        rich_print(table)

    def parse_cookies(self, data: httpx.Response | httpx.Request):
        rich = self._load_rich()
        if rich is None:
            return
        rich_print, _, _, Table, box = rich
        table = Table(**self.styles["table"], box=box.ROUNDED)
        table.add_column("Cookie", style="dim", width=30)
        table.add_column("Value")

        for key in (k for k in data.headers.keys() if k.lower().endswith("cookie")):
            cookies_string = data.headers.get(key, "")
            cookies = SimpleCookie()
            for cookie_string in re.split(", ", cookies_string):
                cookies.load(cookie_string)
            for cookie_name, morsel in cookies.items():
                table.add_row(cookie_name, self.h_(morsel.value))

        if table.row_count > 0:
            rich_print(table)

    def parse_body(self, data: httpx.Response | httpx.Request):
        rich = self._load_rich()
        if rich is None:
            return
        rich_print, JSON, _, Table, box = rich
        table = Table(**self.styles["table"], box=box.ROUNDED)
        table.add_column("Body")
        body = self.h_(data.content.decode(errors="replace"))
        if cast(str, data.headers.get("content-type", "")).startswith("application/json"):
            try:
                body = JSON(body, indent=2)
            except JSONDecodeError:
                body = self.h_(body)
        table.add_row(body)
        rich_print(table)

    def log_request(self, request: httpx.Request):
        rich = self._load_rich()
        if rich is None:
            return
        rich_print, _, Panel, _, box = rich
        rich_print(Panel(f"HTTP 1.1 {request.url}", title="Request", **self.styles["panel"], box=box.ROUNDED))
        self.parse_headers(request)
        self.parse_cookies(request)
        self.parse_body(request)

    def log_response(self, response: httpx.Response):
        rich = self._load_rich()
        if rich is None:
            return
        rich_print, _, Panel, _, box = rich
        rich_print(
            Panel(
                f"{response.status_code} {response.reason_phrase}",
                title="Response",
                **self.styles["panel"],
                box=box.ROUNDED,
            )
        )
        self.parse_headers(response)
        self.parse_cookies(response)
        self.parse_body(response)

    @staticmethod
    def log_response_hook(response: httpx.Response):
        hook = ConsoleTelemetryHook()
        hook.log_request(response.request)
        response.read()
        hook.log_response(response)

    @staticmethod
    async def async_log_response_hook(response: httpx.Response):
        hook = ConsoleTelemetryHook()
        hook.log_request(response.request)
        await response.aread()
        hook.log_response(response)


class ConsoleLogResponse(httpx.Response):
    def iter_bytes(self, *args, **kwargs):
        yield from super().iter_bytes(*args, **kwargs)


class ConsoleLogTransport(httpx.BaseTransport):
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.transport = transport or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = cast(httpx.BaseTransport, self.transport).handle_request(request)
        return ConsoleLogResponse(
            status_code=response.status_code,
            headers=response.headers,
            stream=response.stream,
            extensions=response.extensions,
        )


class AsyncConsoleLogTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.transport = transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await cast(httpx.AsyncBaseTransport, self.transport).handle_async_request(request)
        return ConsoleLogResponse(
            status_code=response.status_code,
            headers=response.headers,
            stream=response.stream,
            extensions=response.extensions,
        )


# Compatibility aliases for legacy imports.
LoggerHook = ConsoleTelemetryHook
LogTransport = ConsoleLogTransport
AsyncLogTransport = AsyncConsoleLogTransport


__all__ = [
    "AsyncConsoleLogTransport",
    "AsyncLogTransport",
    "ConsoleLogTransport",
    "ConsoleTelemetryHook",
    "LoggerHook",
    "LogTransport",
    "console_http_telemetry_enabled",
]
