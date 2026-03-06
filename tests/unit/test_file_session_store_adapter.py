from __future__ import annotations

from pathlib import Path

import pytest

from pyicloud.platform.storage import FileSessionStoreAdapter


def test_file_session_store_save_and_load(tmp_path: Path):
    store = FileSessionStoreAdapter(root_dir=tmp_path)
    payload = {"webservices": {"findme": {"status": "active"}}}

    store.save("user@example.com", payload)

    assert store.load("user@example.com") == payload


def test_file_session_store_clear(tmp_path: Path):
    store = FileSessionStoreAdapter(root_dir=tmp_path)
    store.save("user@example.com", {"ok": True})

    store.clear("user@example.com")

    assert store.load("user@example.com") is None


def test_file_session_store_rejects_invalid_json(tmp_path: Path):
    store = FileSessionStoreAdapter(root_dir=tmp_path)
    file_path = tmp_path / "userexamplecom.json"
    file_path.write_text("{bad json", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Invalid session store payload"):
        _ = store.load("user@example.com")
