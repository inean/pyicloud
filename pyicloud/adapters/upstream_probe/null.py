"""No-op upstream traffic probe adapter."""

from __future__ import annotations

from pyicloud.ports import UpstreamErrorEvent, UpstreamRequestEvent, UpstreamResponseEvent, UpstreamTrafficProbePort


class NullUpstreamTrafficProbeAdapter(UpstreamTrafficProbePort):
    """Drop upstream probe events while keeping instrumentation call sites stable."""

    def on_request(self, event: UpstreamRequestEvent) -> None:  # noqa: ARG002
        return None

    def on_response(self, event: UpstreamResponseEvent) -> None:  # noqa: ARG002
        return None

    def on_error(self, event: UpstreamErrorEvent) -> None:  # noqa: ARG002
        return None
