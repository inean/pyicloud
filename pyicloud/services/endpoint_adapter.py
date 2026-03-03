"""Legacy service endpoint adapter for incremental migration off pyicloud.base."""

from __future__ import annotations

from typing import Any

from pyicloud.models.settings import Settings


class LegacyServiceEndpointAdapter:
    """Adapter exposing the minimal endpoint interface required by PyiCloudServices."""

    __slots__ = ("_webservices", "session", "params", "config", "apple_id")

    def __init__(
        self,
        api: dict[str, Any],
        *,
        settings: Settings,
        session: Any,
        params: dict[str, Any] | None = None,
    ):
        webservices = api.get("webservices", {})
        if not isinstance(webservices, dict):
            raise ValueError("Invalid api payload: missing webservices mapping")

        merged_params = dict(params or {})
        merged_params.setdefault("clientId", settings.client_settings.client_id)

        self._webservices = webservices
        self.session = session
        self.params = merged_params
        self.config = settings
        self.apple_id = settings.account.username

    def authenticate(self, service: str | None = None) -> None:
        """No-op compatibility hook used by PyiCloudServices lazy proxies."""
        if service is not None and service not in self._webservices:
            raise KeyError(f"Service not available: {service}")

    def __contains__(self, service: str) -> bool:
        return service in self._webservices

    def __getitem__(self, service: str) -> str:
        item = self._webservices[service]
        if not isinstance(item, dict) or "url" not in item:
            raise KeyError(f"Service entry has no url: {service}")
        return str(item["url"])
