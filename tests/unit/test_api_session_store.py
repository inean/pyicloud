from __future__ import annotations

from pyicloud.adapters.session import FileApiSessionStore, InMemoryApiSessionStore


def test_in_memory_api_session_store_expiry_and_revocation() -> None:
    now = [100.0]
    store = InMemoryApiSessionStore(clock=lambda: now[0])

    store.put_challenge(challenge_id="challenge-1", payload={"username": "user@example.com"}, ttl_seconds=10)
    assert store.get_challenge("challenge-1") == {"username": "user@example.com"}

    now[0] = 111.0
    assert store.get_challenge("challenge-1") is None

    store.revoke_token(token_id="token-1", ttl_seconds=5)
    assert store.is_token_revoked("token-1") is True
    now[0] = 117.0
    assert store.is_token_revoked("token-1") is False


def test_file_api_session_store_persists_across_instances(tmp_path) -> None:
    now = [1000.0]
    store = FileApiSessionStore(root_dir=tmp_path, clock=lambda: now[0])

    store.put_challenge(challenge_id="challenge-1", payload={"username": "user@example.com"}, ttl_seconds=20)
    store.revoke_token(token_id="token-1", ttl_seconds=20)

    second = FileApiSessionStore(root_dir=tmp_path, clock=lambda: now[0])
    assert second.get_challenge("challenge-1") == {"username": "user@example.com"}
    assert second.is_token_revoked("token-1") is True

    now[0] = 1025.0
    assert second.get_challenge("challenge-1") is None
    assert second.is_token_revoked("token-1") is False
