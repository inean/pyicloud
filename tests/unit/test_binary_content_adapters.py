from __future__ import annotations

import pytest

from pyicloud.adapters.services.content import PhotoBinaryContentAdapter, UbiquityBinaryContentAdapter


class _FakeStreamReader:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.calls: list[object] = []

    def read_stream(self, response: object) -> bytes:
        self.calls.append(response)
        return self.payload


class _FakeAsset:
    def __init__(self, response: object | None):
        self._response = response

    def download(self, *, version: str, stream: bool):  # noqa: ARG002
        return self._response


class _FakeNode:
    def __init__(self, *, node_type: str, response: object):
        self.type = node_type
        self._response = response

    def open(self, *, stream: bool):  # noqa: ARG002
        class _Ctx:
            def __init__(self, response: object):
                self._response = response

            def __enter__(self):
                return self._response

            def __exit__(self, exc_type, exc, tb):  # noqa: ANN001, ANN201
                return None

        return _Ctx(self._response)


def test_photo_binary_content_adapter_reads_stream() -> None:
    response = object()
    stream_reader = _FakeStreamReader(b"photo-bytes")
    adapter = PhotoBinaryContentAdapter(stream_reader=stream_reader)

    payload = adapter.download(asset=_FakeAsset(response), version="original")

    assert payload == b"photo-bytes"
    assert stream_reader.calls == [response]


def test_photo_binary_content_adapter_raises_when_version_missing() -> None:
    adapter = PhotoBinaryContentAdapter(stream_reader=_FakeStreamReader(b"unused"))

    with pytest.raises(KeyError, match="Photo version not found: thumb"):
        adapter.download(asset=_FakeAsset(None), version="thumb")


def test_ubiquity_binary_content_adapter_reads_file_stream() -> None:
    response = object()
    stream_reader = _FakeStreamReader(b"doc-bytes")
    adapter = UbiquityBinaryContentAdapter(stream_reader=stream_reader)

    payload = adapter.read_file(node=_FakeNode(node_type="file", response=response))

    assert payload == b"doc-bytes"
    assert stream_reader.calls == [response]


def test_ubiquity_binary_content_adapter_rejects_non_file_node() -> None:
    adapter = UbiquityBinaryContentAdapter(stream_reader=_FakeStreamReader(b"unused"))

    with pytest.raises(KeyError, match="Ubiquity path is not a file"):
        adapter.read_file(node=_FakeNode(node_type="folder", response=object()))
