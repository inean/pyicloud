"""Library base file."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, override

import async_btree as bt

from pyicloud.trees import TreeState, TreeTransitionExtra
from pyicloud.trees.session import SessionModelTree
from pyicloud.trees.setup import SetupModelTree


class RenewModelTree(SessionModelTree):
    def __init__(
        self,
        *,
        setup_model: SetupModelTree,
        context: dict[str, Any] | None = None,
    ):
        super().__init__(
            settings=setup_model.settings,
            cookies=setup_model.cookies,
            context=context,
        )
        # FIXME: May be call to setup_model.context.update(context) ?
        self._setup_model: SetupModelTree = setup_model

    @property
    def setup_model(self) -> SetupModelTree:
        return self._setup_model

    @property
    def transitions(self) -> Sequence[TreeTransitionExtra]:
        return [
            {
                "trigger": "renew",
                "source": TreeState.SESSION_CLOSED,
                "dest": TreeState.SESSION_ACTIVE,
                "action": self.run,
                "result": "api",
                "on_result": lambda results: results[-1],
            },
        ]

    @property
    @override
    def bhtree(self) -> bt.AsyncInnerFunction:
        renew_subtree = bt.sequence(
            children=[
                # Check if a previos loggin attempt was successfull.
                # Even if session is no longer valid, presence of serssion
                # token will allow us to omit 2FA if needed
                self._session_is_logged,
                bt.retry(
                    child=bt.decision(
                        condition=self._session_is_valid,
                        success_tree=bt.action(self.session_validate),
                        failure_tree=bt.action(self._setup_model.bhtree),
                    ),
                    max_retry=1,
                ),
            ]
        )
        return renew_subtree
