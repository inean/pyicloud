import re
from http.cookies import SimpleCookie
from typing import Any, cast

import httpx
from rich import box, print
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from pyicloud.log import hide_sensitive_data


async def log_response_hook(response: httpx.Response):
    h_ = lambda value: hide_sensitive_data(value)  # noqa

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

    def log_headers(data: httpx.Response | httpx.Request):
        table = Table(**styles["table"])
        table.add_column("Header", style="gold3", width=30)
        table.add_column("Value")
        for key, value in ((k, v) for k, v in data.headers.items() if not k.lower().endswith("cookie")):
            table.add_row(key, h_(value))
        print(table)

    def log_cookies(data: httpx.Response | httpx.Request):
        table = Table(**styles["table"])
        table.add_column("Cookie", style="dim", width=30)
        table.add_column("Value")

        for key in (key for key in data.headers.keys() if key.lower().endswith("cookie")):
            cookies_string = data.headers.get(key, "")
            cookies = SimpleCookie()
            for cookie_string in re.split(", ", cookies_string):
                cookies.load(cookie_string)
            for key, morsel in cookies.items():
                table.add_row(key, h_(morsel.value))

        if table.row_count > 0:
            print(table)

    def log_body(data: httpx.Response | httpx.Request):
        table = Table(**styles["table"])
        table.add_column("Body")
        body = h_(data.content.decode())
        if cast(str, data.headers.get("content-type", "")).startswith("application/json"):
            body = JSON(body, indent=2)
        table.add_row(body)
        print(table)

    def log_request(request: httpx.Request):
        print(Panel(f"HTTP 1.1 {request.url}", title="Request", **styles["panel"]))
        log_headers(request)
        log_cookies(request)
        log_body(request)

    def log_response(response: httpx.Response):
        print(Panel(f"{response.status_code} {response.reason_phrase}", title="Response", **styles["panel"]))
        log_headers(response)
        log_cookies(response)
        log_body(response)

    log_request(response.request)
    await response.aread()
    log_response(response)


class LogResponse(httpx.Response):
    def iter_bytes(self, *args, **kwargs):
        for chunk in super().iter_bytes(*args, **kwargs):
            print(chunk)
            yield chunk


class LogTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport):
        self.transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.transport.handle_async_request(request)

        return LogResponse(
            status_code=response.status_code,
            headers=response.headers,
            stream=response.stream,
            extensions=response.extensions,
        )


def AsyncLogClient(**kwargs: Any) -> httpx.AsyncClient:
    kwargs.setdefault("follow_redirects", True)
    kwargs.update(
        transport=LogTransport(httpx.AsyncHTTPTransport()),
        event_hooks={"response": [log_response_hook]},
    )
    return httpx.AsyncClient(**kwargs)
