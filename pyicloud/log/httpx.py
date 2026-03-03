import re
from http.cookies import SimpleCookie
from json import JSONDecodeError
from typing import cast

import httpx
from rich import box, print
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from pyicloud.log import hide_sensitive_data


class LoggerHook:
    styles = {
        "table": {
            "title_justify": "left",
            "box": box.ROUNDED,
            "width": 100,
        },
        "panel": {
            "title_align": "left",
            "box": box.ROUNDED,
            "width": 100,
        },
    }

    h_ = staticmethod(lambda value: hide_sensitive_data(value))  # noqa

    def parse_headers(self, data: httpx.Response | httpx.Request):
        table = Table(**self.styles["table"])
        table.add_column("Header", style="gold3", width=30)
        table.add_column("Value")
        for key, value in ((k, v) for k, v in data.headers.items() if not k.lower().endswith("cookie")):
            table.add_row(key, self.h_(value))
        print(table)

    def parse_cookies(self, data: httpx.Response | httpx.Request):
        table = Table(**self.styles["table"])
        table.add_column("Cookie", style="dim", width=30)
        table.add_column("Value")

        for key in (k for k in data.headers.keys() if k.lower().endswith("cookie")):
            cookies_string = data.headers.get(key, "")
            cookies = SimpleCookie()
            for cookie_string in re.split(", ", cookies_string):
                cookies.load(cookie_string)
            for key, morsel in cookies.items():
                table.add_row(key, self.h_(morsel.value))

        if table.row_count > 0:
            print(table)

    def parse_body(self, data: httpx.Response | httpx.Request):
        table = Table(**self.styles["table"])
        table.add_column("Body")
        body = self.h_(data.content.decode())
        if cast(str, data.headers.get("content-type", "")).startswith("application/json"):
            try:
                body = JSON(body, indent=2)
            except JSONDecodeError:
                body = self.h_(body)
        table.add_row(body)
        print(table)

    def log_request(self, request: httpx.Request):
        print(Panel(f"HTTP 1.1 {request.url}", title="Request", **self.styles["panel"]))
        self.parse_headers(request)
        self.parse_cookies(request)
        self.parse_body(request)

    def log_response(self, response: httpx.Response):
        print(Panel(f"{response.status_code} {response.reason_phrase}", title="Response", **self.styles["panel"]))
        self.parse_headers(response)
        self.parse_cookies(response)
        self.parse_body(response)

    @staticmethod
    def log_response_hook(response: httpx.Response):
        hook = LoggerHook()
        hook.log_request(response.request)
        response.read()
        hook.log_response(response)

    @staticmethod
    async def async_log_response_hook(response: httpx.Response):
        hook = LoggerHook()
        hook.log_request(response.request)
        await response.aread()
        hook.log_response(response)


class LogResponse(httpx.Response):
    def iter_bytes(self, *args, **kwargs):
        for chunk in super().iter_bytes(*args, **kwargs):
            yield chunk


class LogTransport(httpx.BaseTransport):
    def __init__(self, transport: httpx.BaseTransport | None = None):
        transport = transport or httpx.HTTPTransport()
        self.transport = transport

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = cast(httpx.BaseTransport, self.transport).handle_request(request)

        return LogResponse(
            status_code=response.status_code,
            headers=response.headers,
            stream=response.stream,
            extensions=response.extensions,
        )


class AsyncLogTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.transport = transport or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await cast(httpx.AsyncBaseTransport, self.transport).handle_async_request(request)

        return LogResponse(
            status_code=response.status_code,
            headers=response.headers,
            stream=response.stream,
            extensions=response.extensions,
        )
