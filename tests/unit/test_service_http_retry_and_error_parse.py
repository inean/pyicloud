from __future__ import annotations

from collections import deque

import httpx
import pytest

from pyicloud.adapters.session.service_http import LegacyServiceSessionAdapter
from pyicloud.exceptions import PyiCloudAPIResponseError
from pyicloud.models.settings import Settings


def test_service_http_retries_once_for_retryable_status(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings.create(username="user@example.com", password="secret")
    requests: list[tuple[str, str]] = []
    responses = deque(
        [
            httpx.Response(
                500,
                headers={"content-type": "text/plain"},
                content=b"upstream-error",
                request=httpx.Request("GET", "https://example.test/retry"),
            ),
            httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={},
                request=httpx.Request("GET", "https://example.test/retry"),
            ),
        ]
    )

    def fake_request(self, method, url, **kwargs):  # noqa: ARG001
        requests.append((method, url))
        return responses.popleft()

    monkeypatch.setattr(httpx.Client, "request", fake_request)

    session = LegacyServiceSessionAdapter(settings=settings)
    try:
        response = session.request("GET", "https://example.test/retry")
    finally:
        session.close()

    assert response.status_code == 200
    assert requests == [
        ("GET", "https://example.test/retry"),
        ("GET", "https://example.test/retry"),
    ]


def test_service_http_error_parser_prefers_domain_error_fields() -> None:
    settings = Settings.create(username="user@example.com", password="secret")
    captured: list[tuple[str | int | None, str]] = []

    session = LegacyServiceSessionAdapter(
        settings=settings,
        error_callback=lambda code, reason: captured.append((code, reason)),
    )
    try:
        session._parse_error(  # noqa: SLF001
            {
                "errorReason": "failure-reason",
                "serverErrorCode": "5002",
            }
        )
    finally:
        session.close()

    assert captured == [("5002", "failure-reason")]


def test_service_http_error_parser_raises_for_string_error() -> None:
    settings = Settings.create(username="user@example.com", password="secret")
    session = LegacyServiceSessionAdapter(settings=settings)
    try:
        with pytest.raises(PyiCloudAPIResponseError, match="Bad auth"):
            session._parse_error({"error": "Bad auth"})  # noqa: SLF001
    finally:
        session.close()
