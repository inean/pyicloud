from __future__ import annotations

from pyicloud.platform.legacy_auth_tree.engine import BehaveTree as CanonicalBehaveTree
from pyicloud.platform.legacy_auth_tree.engine import TreeState as CanonicalTreeState
from pyicloud.platform.legacy_auth_tree.session import SessionModelTree as CanonicalSessionModelTree
from pyicloud.platform.legacy_auth_tree.setup import SetupHooks as CanonicalSetupHooks
from pyicloud.platform.legacy_auth_tree.setup import SetupModelTree as CanonicalSetupModelTree
from pyicloud.trees import BehaveTree, TreeState
from pyicloud.trees.session import SessionModelTree
from pyicloud.trees.setup import SetupHooks, SetupModelTree


def test_trees_engine_alias_reexports_canonical_symbols() -> None:
    assert BehaveTree is CanonicalBehaveTree
    assert TreeState is CanonicalTreeState


def test_trees_session_and_setup_alias_reexports_canonical_symbols() -> None:
    assert SessionModelTree is CanonicalSessionModelTree
    assert SetupHooks is CanonicalSetupHooks
    assert SetupModelTree is CanonicalSetupModelTree
