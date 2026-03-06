from __future__ import annotations

from pyicloud.platform.telemetry.upstream.sanitize import sanitize_body, sanitize_headers


def test_sanitize_headers_redacts_sensitive_values_and_cookies():
    headers, cookies = sanitize_headers(
        {
            "Authorization": "Bearer top-secret-token",
            "X-Apple-Session-Token": "session-token",
            "Content-Type": "application/json",
            "Cookie": "sessionid=abc123; csrftoken=def456",
        }
    )

    assert headers["authorization"]["present"] is True
    assert headers["authorization"]["sha256"]
    assert headers["x-apple-session-token"]["present"] is True
    assert headers["content-type"] == "application/json"
    assert cookies["sessionid"]["present"] is True
    assert cookies["csrftoken"]["present"] is True


def test_sanitize_body_redacts_sensitive_json_fields():
    body, size = sanitize_body(
        body=b'{"username":"user@example.com","password":"super-secret","token":"abc"}',
        content_type="application/json",
        max_bytes=4096,
    )

    assert size > 0
    assert body["password"]["present"] is True
    assert body["token"]["present"] is True
    assert body["username"] == "user@example.com"


def test_sanitize_body_marks_binary_payloads_without_raw_dump():
    body, size = sanitize_body(
        body=b"\x00\x01\x02\x03",
        content_type="application/octet-stream",
        max_bytes=2,
    )

    assert size == 4
    assert body["binary"] is True
    assert body["length"] == 4
    assert body["sha256"]
