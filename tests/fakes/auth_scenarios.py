"""Fake auth scenario builders for vertical API/CLI tests."""

from __future__ import annotations

from pathlib import Path

from pyicloud.adapters.auth import FakeScenarioAuthSessionAdapter
from pyicloud.adapters.session import InMemoryApiSessionStore
from pyicloud.adapters.store import FileSessionStoreAdapter
from pyicloud.adapters.token import JwtTokenSigner
from pyicloud.application.api_auth import AuthApiService
from pyicloud.application.auth_session import AuthSessionService
from pyicloud.application.core_services import CoreServicesApi

SCENARIO_BY_USERNAME = {
    "success@example.com": "success",
    "requires2fa@example.com": "requires_2fa",
    "invalid@example.com": "invalid_credentials",
    "expired@example.com": "expired_session",
}


class _NoopCoreServices(CoreServicesApi):
    def __init__(self):
        super().__init__(devices=self, accounts=self, drive=self)

    # Device
    def list_devices(self, *, username: str):  # noqa: ARG002
        return []

    def device_location(self, *, username: str, device_id: str):  # noqa: ARG002
        return {"device_id": device_id, "location": None}

    def device_status(self, *, username: str, device_id: str):  # noqa: ARG002
        return {"device_id": device_id}

    def device_play_sound(self, *, username: str, device_id: str, subject: str):  # noqa: ARG002
        return None

    def device_message(self, *, username: str, device_id: str, subject: str, message: str, sounds: bool):  # noqa: ARG002
        return None

    def device_lost_mode(self, *, username: str, device_id: str, number: str, text: str, newpasscode: str):  # noqa: ARG002
        return None

    # Account
    def account_devices(self, *, username: str):  # noqa: ARG002
        return []

    def account_family(self, *, username: str):  # noqa: ARG002
        return []

    def account_storage(self, *, username: str):  # noqa: ARG002
        return {"usage": {}, "usages_by_media": {}}

    # Drive
    def drive_tree(self, *, username: str, path: str):  # noqa: ARG002
        return {"path": path, "children": []}

    def drive_file_metadata(self, *, username: str, path: str):  # noqa: ARG002
        return {"path": path}

    def drive_file_content(self, *, username: str, path: str):  # noqa: ARG002
        return b""

    def drive_create_folder(self, *, username: str, parent_path: str, name: str):  # noqa: ARG002
        return None

    def drive_upload_file(self, *, username: str, parent_path: str, filename: str, content: bytes):  # noqa: ARG002
        return None

    def drive_rename_node(self, *, username: str, path: str, new_name: str):  # noqa: ARG002
        return None

    def drive_delete_node(self, *, username: str, path: str):  # noqa: ARG002
        return None


def build_fake_auth_api_service(tmp_path: Path) -> AuthApiService:
    session_store = InMemoryApiSessionStore()
    signer = JwtTokenSigner(secret="test-secret-at-least-thirty-two-bytes")

    def auth_service_factory(username: str, password: str) -> AuthSessionService:  # noqa: ARG001
        scenario = SCENARIO_BY_USERNAME.get(username, "success")
        adapter = FakeScenarioAuthSessionAdapter(scenario=scenario)
        store = FileSessionStoreAdapter(root_dir=tmp_path / "sessions")
        return AuthSessionService(auth=adapter, store=store)

    return AuthApiService(
        token_signer=signer,
        session_query=session_store,
        session_command=session_store,
        auth_service_factory=auth_service_factory,
        token_ttl_seconds=3600,
        challenge_ttl_seconds=300,
    )


def build_noop_core_services() -> CoreServicesApi:
    return _NoopCoreServices()
