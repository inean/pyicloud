"""Bootstrap helpers for the auth/session application service."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pyicloud.adapters.auth import TreeAuthSessionAdapter
from pyicloud.adapters.auth_state_reset import CookieAuthStateResetPolicy
from pyicloud.adapters.tree_runtime import FileBackedTreeRuntimeAdapter
from pyicloud.application import AuthSessionService
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.platform.storage import FileSessionStoreAdapter
from pyicloud.ports import AuthStateResetPolicy
from pyicloud.trees.setup import SetupHooks, SetupModelTree


def build_auth_session_service(
    *,
    settings: Settings,
    hooks: SetupHooks,
    cookies: Cookies | None = None,
    auth_reset_policy: AuthStateResetPolicy | None = None,
    context: dict[str, Any] | None = None,
    store_dir: str | Path | None = None,
    setup_model_cls: type[SetupModelTree] = SetupModelTree,
) -> AuthSessionService:
    """
    Compose an AuthSessionService with tree-based auth and file-backed persistence.

    Args:
        settings: Account/client settings model.
        hooks: Interaction hooks used by the setup model.
        cookies: Optional preloaded cookie jar model.
        context: Optional blackboard context injected into setup tree model.
        store_dir: Optional root directory for the file session store.
        setup_model_cls: Setup tree implementation, defaults to SetupModelTree.
    """
    if auth_reset_policy is None:
        auth_reset_policy = CookieAuthStateResetPolicy()

    setup_model = setup_model_cls(
        settings=settings,
        cookies=cookies,
        auth_reset_policy=auth_reset_policy,
        hooks=hooks,
        context=context,
    )
    runtime_configurator = getattr(setup_model, "set_runtime_port", None)
    if callable(runtime_configurator):
        runtime_configurator(FileBackedTreeRuntimeAdapter())
    auth_adapter = TreeAuthSessionAdapter(setup_model=setup_model)
    store_adapter = FileSessionStoreAdapter(root_dir=store_dir)
    return AuthSessionService(auth=auth_adapter, store=store_adapter)
