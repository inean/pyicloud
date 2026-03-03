"""Tree-based auth/session adapter scaffold."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pyicloud.ports import AuthSessionPort


class TreeAuthSessionAdapter(AuthSessionPort):
    """Adapter placeholder for SetupModelTree/RenewModelTree integration."""

    async def signin(self, *, refresh_signin: bool) -> bool:
        raise NotImplementedError("Tree auth adapter signin is not implemented yet")

    async def security_code(self, code: str) -> None:
        raise NotImplementedError("Tree auth adapter security_code is not implemented yet")

    async def trust(self) -> None:
        raise NotImplementedError("Tree auth adapter trust is not implemented yet")

    async def account_login(self, *, require_trust_token: bool) -> None:
        raise NotImplementedError("Tree auth adapter account_login is not implemented yet")

    async def session_validate(self) -> Mapping[str, Any]:
        raise NotImplementedError("Tree auth adapter session_validate is not implemented yet")
