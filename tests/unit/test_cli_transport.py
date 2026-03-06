from __future__ import annotations

import pytest

from pyicloud.cli import transport


@pytest.mark.asyncio
async def test_complete_auth_challenge_uses_vault_password_without_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    prompts: list[str] = []

    def _unexpected_prompt(text: str, **_kwargs):
        prompts.append(text)
        raise AssertionError(f"Prompt should not be called: {text}")

    monkeypatch.setattr(transport.click, "prompt", _unexpected_prompt)

    calls: list[tuple[str, dict[str, object] | None]] = []

    async def fake_request_json_data_fn(
        *,
        api_url: str,  # noqa: ARG001
        method: str,  # noqa: ARG001
        route: str,
        token: str | None = None,  # noqa: ARG001
        json_body: dict[str, object] | None = None,
    ):
        calls.append((route, json_body))
        if route == "/v1/auth/login":
            assert json_body is not None
            assert json_body["username"] == "vault-user@example.com"
            assert json_body["password"] == "vault-secret"
            return {"status": "authenticated", "access_token": "token-1"}
        raise AssertionError(f"Unexpected route: {route}")

    saved_tokens: list[str] = []
    saved_passwords: list[tuple[str, str]] = []

    await transport.complete_auth_challenge(
        api_url="http://testserver",
        challenge={"account_id": "vault-user@example.com"},
        request_json_data_fn=fake_request_json_data_fn,
        save_token_fn=lambda token: saved_tokens.append(token),
        load_password_fn=lambda username: "vault-secret" if username == "vault-user@example.com" else None,
        save_password_fn=lambda username, password: saved_passwords.append((username, password)),
    )

    assert prompts == []
    assert calls == [
        (
            "/v1/auth/login",
            {"username": "vault-user@example.com", "password": "vault-secret"},
        )
    ]
    assert saved_tokens == ["token-1"]
    assert saved_passwords == [("vault-user@example.com", "vault-secret")]


@pytest.mark.asyncio
async def test_complete_auth_challenge_prompts_when_vault_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    prompt_calls: list[str] = []

    def _prompt(text: str, **_kwargs):
        prompt_calls.append(text)
        if text.startswith("Password for "):
            return "typed-secret"
        if text == "Security code":
            return "123456"
        raise AssertionError(f"Unexpected prompt: {text}")

    monkeypatch.setattr(transport.click, "prompt", _prompt)

    calls: list[tuple[str, dict[str, object] | None]] = []

    async def fake_request_json_data_fn(
        *,
        api_url: str,  # noqa: ARG001
        method: str,  # noqa: ARG001
        route: str,
        token: str | None = None,  # noqa: ARG001
        json_body: dict[str, object] | None = None,
    ):
        calls.append((route, json_body))
        if route == "/v1/auth/login":
            return {"status": "challenge_required", "challenge_id": "challenge-1"}
        if route == "/v1/auth/security-code":
            assert json_body is not None
            assert json_body["password"] == "typed-secret"
            assert json_body["username"] == "typed-user@example.com"
            return {"status": "authenticated", "access_token": "token-2"}
        raise AssertionError(f"Unexpected route: {route}")

    saved_tokens: list[str] = []
    saved_passwords: list[tuple[str, str]] = []

    await transport.complete_auth_challenge(
        api_url="http://testserver",
        challenge={"account_id": "typed-user@example.com", "flow_id": "flow-123"},
        request_json_data_fn=fake_request_json_data_fn,
        save_token_fn=lambda token: saved_tokens.append(token),
        load_password_fn=lambda _username: None,
        save_password_fn=lambda username, password: saved_passwords.append((username, password)),
    )

    assert prompt_calls == ["Password for typed-user@example.com", "Security code"]
    assert calls == [
        (
            "/v1/auth/login",
            {"username": "typed-user@example.com", "password": "typed-secret", "flow_id": "flow-123"},
        ),
        (
            "/v1/auth/security-code",
            {
                "challenge_id": "challenge-1",
                "code": "123456",
                "password": "typed-secret",
                "username": "typed-user@example.com",
            },
        ),
    ]
    assert saved_tokens == ["token-2"]
    assert saved_passwords == [("typed-user@example.com", "typed-secret")]
