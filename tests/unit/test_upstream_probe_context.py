from __future__ import annotations

from pyicloud.upstream.context import bind_upstream_context, current_upstream_context, ensure_upstream_context


def test_ensure_upstream_context_generates_flow_and_account_hash():
    ctx = ensure_upstream_context(operation="devices.list", username="User@example.com")

    assert ctx["flow_id"]
    assert ctx["operation"] == "devices.list"
    assert ctx["account_hash"]


def test_bind_upstream_context_is_scoped():
    parent = ensure_upstream_context(operation="auth.bootstrap", username="a@example.com")
    with bind_upstream_context(operation="devices.list", step="find_devices") as child:
        inside = current_upstream_context()
        assert inside["operation"] == "devices.list"
        assert inside["step"] == "find_devices"
        assert inside["flow_id"] == child["flow_id"]

    after = current_upstream_context()
    assert after["operation"] == parent["operation"]
