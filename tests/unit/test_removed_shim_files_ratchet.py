from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

REMOVED_SHIM_PATHS = (
    "pyicloud/upstream/__init__.py",
    "pyicloud/upstream/classification.py",
    "pyicloud/upstream/context.py",
    "pyicloud/upstream/events.py",
    "pyicloud/upstream/runtime.py",
    "pyicloud/upstream/sanitize.py",
    "pyicloud/adapters/store/__init__.py",
    "pyicloud/adapters/store/file_session_store.py",
    "pyicloud/adapters/services/runtime.py",
    "pyicloud/application/access_control.py",
    "pyicloud/application/api_auth.py",
    "pyicloud/application/auth_abuse_guard.py",
    "pyicloud/application/auth_session.py",
    "pyicloud/application/observability.py",
    "pyicloud/application/operation_suspension.py",
    "pyicloud/application/service_endpoint_restore.py",
    "pyicloud/trees/renew.py",
)


def test_removed_shim_files_do_not_reappear() -> None:
    reintroduced = [rel_path for rel_path in REMOVED_SHIM_PATHS if (REPO_ROOT / rel_path).exists()]
    assert reintroduced == [], f"Removed shim files reintroduced: {reintroduced}"
