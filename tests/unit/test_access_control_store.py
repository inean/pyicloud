from __future__ import annotations

from pyicloud.adapters.access import FileAccessControlStore, InMemoryAccessControlStore


def test_in_memory_access_control_store_upsert_and_counts() -> None:
    now = [100.0]
    store = InMemoryAccessControlStore(clock=lambda: now[0])

    created = store.upsert_entry(
        username="Admin@Example.com",
        roles=("admin",),
        status="active",
        actor="bootstrap",
    )
    assert created.username == "admin@example.com"
    assert created.roles == ("admin",)
    assert created.acl_version == 1
    assert store.active_admin_count() == 1

    unchanged = store.upsert_entry(
        username="admin@example.com",
        roles=("admin",),
        status="active",
        actor="bootstrap",
    )
    assert unchanged.acl_version == 1

    now[0] = 150.0
    demoted = store.upsert_entry(
        username="admin@example.com",
        roles=("member",),
        status="active",
        actor="admin@example.com",
    )
    assert demoted.acl_version == 2
    assert demoted.updated_at == 150
    assert store.active_admin_count() == 0

    assert store.delete_entry(username="admin@example.com", actor="admin@example.com") is True
    assert store.get_entry("admin@example.com") is None
    assert store.delete_entry(username="admin@example.com", actor="admin@example.com") is False


def test_file_access_control_store_persists_across_instances(tmp_path) -> None:
    now = [1000.0]
    store = FileAccessControlStore(root_dir=tmp_path, clock=lambda: now[0])

    store.upsert_entry(
        username="admin@example.com",
        roles=("admin",),
        status="active",
        actor="bootstrap",
    )
    store.upsert_entry(
        username="member@example.com",
        roles=("member",),
        status="active",
        actor="admin@example.com",
    )

    second = FileAccessControlStore(root_dir=tmp_path, clock=lambda: now[0])
    listing = second.list_entries()
    assert [entry.username for entry in listing] == ["admin@example.com", "member@example.com"]
    assert second.active_admin_count() == 1

    now[0] = 1010.0
    updated = second.upsert_entry(
        username="member@example.com",
        roles=("member",),
        status="disabled",
        actor="admin@example.com",
    )
    assert updated.acl_version == 2
    assert updated.updated_at == 1010
