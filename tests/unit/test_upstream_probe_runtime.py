from __future__ import annotations

import pytest

from pyicloud.adapters.upstream_probe.runtime import reset_upstream_probe_cache, validate_upstream_probe_configuration


@pytest.fixture(autouse=True)
def _clear_probe_cache():
    reset_upstream_probe_cache()
    yield
    reset_upstream_probe_cache()


def test_upstream_probe_guardrail_blocks_capture_outside_allowed_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PYICLOUD_UPSTREAM_CAPTURE_ENABLED", "true")
    monkeypatch.setenv("PYICLOUD_UPSTREAM_ALLOWED_ENVS", "dev,qa")
    monkeypatch.setenv("PYICLOUD_API_ENV", "prod")

    with pytest.raises(RuntimeError, match="not allowed"):
        validate_upstream_probe_configuration()


def test_upstream_probe_guardrail_allows_capture_in_qa(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PYICLOUD_UPSTREAM_CAPTURE_ENABLED", "true")
    monkeypatch.setenv("PYICLOUD_UPSTREAM_ALLOWED_ENVS", "dev,qa")
    monkeypatch.setenv("PYICLOUD_API_ENV", "qa")

    validate_upstream_probe_configuration()
