"""Explicit binary/content handling adapters for streaming downloads."""

from __future__ import annotations

from typing import Any

from pyicloud.platform.provider.runtime import ServiceRuntime


class StreamingBinaryContentAdapter:
    """Read bytes from streaming response objects."""

    def read_stream(self, response: Any) -> bytes:
        return ServiceRuntime.stream_bytes(response)


class PhotoBinaryContentAdapter:
    """Handle photo asset binary download behavior."""

    def __init__(self, *, stream_reader: StreamingBinaryContentAdapter | None = None):
        self._stream_reader = stream_reader or StreamingBinaryContentAdapter()

    def download(self, *, asset: Any, version: str) -> bytes:
        response = asset.download(version=version, stream=True)
        if response is None:
            raise KeyError(f"Photo version not found: {version}")
        return self._stream_reader.read_stream(response)


class UbiquityBinaryContentAdapter:
    """Handle ubiquity file binary download behavior."""

    def __init__(self, *, stream_reader: StreamingBinaryContentAdapter | None = None):
        self._stream_reader = stream_reader or StreamingBinaryContentAdapter()

    def read_file(self, *, node: Any) -> bytes:
        if str(node.type) != "file":
            raise KeyError("Ubiquity path is not a file")
        with node.open(stream=True) as response:
            return self._stream_reader.read_stream(response)
