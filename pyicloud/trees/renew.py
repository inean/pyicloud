"""Library base file."""

from __future__ import annotations

import async_btree as bt

from . import BehaveTree, ModelTree


class RenewModelTree(ModelTree):
    async def _session_is_logged_in(self): ...
    async def _session_is_2fa_pending(self): ...
    async def _session_is_expired(self): ...
    async def _session_renew(self): ...


class iRenewTree(BehaveTree[RenewModelTree]):
    def _setup(self):
        return bt.sequence(
            children=[
                bt.condition(self._model._session_is_logged_in),
                bt.condition(bt.inverter(self._model._session_is_2fa_pending)),
                bt.condition(bt.inverter(self._model._session_is_expired)),
                bt.always_success(child=self._model._session_renew),
            ]
        )
