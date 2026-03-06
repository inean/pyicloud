from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from pyicloud.constants import AppleCookies as Jar
from pyicloud.models.bodies import BodyModel
from pyicloud.models.cookies import Cookies, CookiesModel
from pyicloud.models.errors import Error
from pyicloud.models.headers import HeadersModel
from pyicloud.models.settings import Settings
from pyicloud.sessions import (
    AppleSessionTransport,
    BaseResponse,
    OAuthTransport,
    SerializationInfo,
    Serialize,
    SessionTransport,
    serialize,
)
from pyicloud.sessions.validate import Validate, ValidateRequest, ValidateResponse
from pyicloud.utils.context import sync_context
from tests.const import AUTHENTICATED_USER, SCNT, SESSION_ID, VALID_TOKEN


@pytest.fixture
def validate_settings() -> Settings:
    with patch("locale.getlocale", return_value=["en_US", "UTF-8"]):
        return Settings.model_validate(
            {
                "account": {
                    "username": AUTHENTICATED_USER,
                    "session_id": SESSION_ID,
                },
                "token": {
                    "session": VALID_TOKEN,
                    "trust": VALID_TOKEN,
                },
                "client_settings": {
                    "scnt": SCNT,
                },
            },
        )


@pytest.fixture
def validate_cookies_with_domain_mismatch() -> Cookies:
    return Cookies.model_validate(
        {
            Jar.DSLANG: {"name": Jar.DSLANG, "value": "US-EN", "domain": ".apple.com"},
            Jar.SITE: {"name": Jar.SITE, "value": "USA", "domain": ".apple.com"},
            Jar.WEBAUTH_USER: {"name": Jar.WEBAUTH_USER, "value": "webauth_user", "domain": ".apple.com"},
            Jar.WEBAUTH_TOKEN: {"name": Jar.WEBAUTH_TOKEN, "value": VALID_TOKEN, "domain": ".apple.com"},
            Jar.WEBAUTH_VALIDATE: {
                "name": Jar.WEBAUTH_VALIDATE,
                "value": VALID_TOKEN,
                "domain": ".apple.com",
            },
            Jar.WEB_SESSION_TOKEN: {
                "name": Jar.WEB_SESSION_TOKEN,
                "value": "session_token",
                "domain": ".apple.com",
            },
        },
    )


def test_dump_headers_casts_non_string_values(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
    monkeypatch: pytest.MonkeyPatch,
):
    user = Validate(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    settings_cls = type(user._settings)
    monkeypatch.setattr(
        settings_cls,
        "model_dump_by_meta",
        lambda self, *args, **kwargs: {
            "x-bool": True,
            "x-int": 42,
            "x-string": "ok",
        },
    )

    headers = user.dump_headers()

    assert headers["x-bool"] == "true"
    assert headers["x-int"] == "42"
    assert headers["x-string"] == "ok"


def test_create_request_rebinds_locale_domains_and_warns_for_non_locale_cookies(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
    caplog: pytest.LogCaptureFixture,
):
    user = Validate(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    with caplog.at_level("WARNING"):
        request = user.request.create_request()

    cookie_header = request.headers.get("cookie", "")
    assert Jar.DSLANG in cookie_header
    assert Jar.SITE in cookie_header
    assert Jar.WEBAUTH_USER in cookie_header

    warnings = [record.message for record in caplog.records if "domain mismatch" in record.message]
    assert any(Jar.WEBAUTH_USER in message for message in warnings)
    assert not any(Jar.DSLANG in message for message in warnings)
    assert not any(Jar.SITE in message for message in warnings)


def _build_serializable_transport(
    *,
    settings: Serialize | dict[str, object] | None = None,
    cookies: Serialize | dict[str, object] | None = None,
) -> type[OAuthTransport]:
    class PlainValidate(OAuthTransport[ValidateRequest, ValidateResponse]):
        pass

    return serialize(PlainValidate, settings=settings, cookies=cookies)


def _build_plain_transport() -> type[OAuthTransport]:
    class PlainValidate(OAuthTransport[ValidateRequest, ValidateResponse]):
        pass

    return PlainValidate


def test_serialize_applies_explicit_serialize_instances(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    wrapped = _build_serializable_transport(
        settings=Serialize(
            read=True,
            write=False,
            options=SerializationInfo(indent=4),
        ),
        cookies=Serialize(
            read=True,
            write=False,
            options=SerializationInfo(indent=6),
        ),
    )
    transport = wrapped(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    assert transport._serialize_settings_.read is True
    assert transport._serialize_settings_.write is False
    assert transport._serialize_settings_.options.indent == 4
    assert transport._serialize_settings_.options.by_alias is True

    assert transport._serialize_cookies_.read is True
    assert transport._serialize_cookies_.write is False
    assert transport._serialize_cookies_.options.indent == 6
    assert transport._serialize_cookies_.options.exclude_defaults is True


def test_serialize_runtime_context_overrides_decorator_options(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    wrapped = _build_serializable_transport(
        settings=Serialize(
            read=True,
            write=False,
            options=SerializationInfo(indent=3),
        ),
        cookies=Serialize(
            read=False,
            write=True,
            options=SerializationInfo(indent=2),
        ),
    )

    with sync_context(
        serialize_info={
            "settings": {"write": True, "options": {"indent": 8}},
            "cookies": Serialize(read=True, options=SerializationInfo(indent=9)),
        }
    ):
        transport = wrapped(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    assert transport._serialize_settings_.read is True
    assert transport._serialize_settings_.write is True
    assert transport._serialize_settings_.options.indent == 8
    assert transport._serialize_settings_.options.by_alias is True

    assert transport._serialize_cookies_.read is True
    assert transport._serialize_cookies_.write is True
    assert transport._serialize_cookies_.options.indent == 9
    assert transport._serialize_cookies_.options.exclude_defaults is True


def test_serialize_dict_options_merge_with_defaults(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    wrapped = _build_serializable_transport(
        settings={"read": True, "options": {"indent": 5}},
        cookies={"options": {"indent": 7}},
    )
    transport = wrapped(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    assert transport._serialize_settings_.read is True
    assert transport._serialize_settings_.write is True
    assert transport._serialize_settings_.options.indent == 5
    assert transport._serialize_settings_.options.by_alias is True

    assert transport._serialize_cookies_.options.indent == 7
    assert transport._serialize_cookies_.options.by_alias is True
    assert transport._serialize_cookies_.options.exclude_unset is True


def test_serialize_does_not_share_mutable_serialize_instances(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    settings_config = Serialize(read=True, options=SerializationInfo(indent=6))
    wrapped = _build_serializable_transport(settings=settings_config)

    first = wrapped(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)
    first._serialize_settings_.read = False
    first._serialize_settings_.options.indent = 99

    second = wrapped(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)

    assert settings_config.read is True
    assert settings_config.options.indent == 6
    assert second._serialize_settings_.read is True
    assert second._serialize_settings_.options.indent == 6


def test_base_response_errors_default_is_not_shared_between_instances() -> None:
    class _TestResponse(BaseResponse[HeadersModel, CookiesModel, BodyModel]):
        pass

    first = _TestResponse(status_code=400, headers=HeadersModel(), cookies=CookiesModel())
    second = _TestResponse(status_code=400, headers=HeadersModel(), cookies=CookiesModel())

    first.errors.append(Error(code=1, message="boom"))

    assert second.errors == []


def test_base_response_create_handles_malformed_json_error_payload_with_fallback() -> None:
    class _TestResponse(BaseResponse[HeadersModel, CookiesModel, BodyModel]):
        pass

    response = httpx.Response(
        500,
        request=httpx.Request("POST", "https://example.test/failure"),
        headers={"content-type": "application/json"},
        content=b'{"serviceErrors": [',
    )

    parsed = _TestResponse.create(response)

    assert parsed.errors
    assert parsed.errors[0].code == 500
    assert "HTTP 500" in parsed.errors[0].message


def test_session_transport_alias_window_exposes_legacy_and_new_names() -> None:
    assert SessionTransport is not None
    assert AppleSessionTransport is not None
    assert OAuthTransport is AppleSessionTransport


async def test_base_transport_does_not_close_injected_client(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    plain_transport = _build_plain_transport()
    client = httpx.AsyncClient()
    transport = plain_transport(
        settings=validate_settings, cookies=validate_cookies_with_domain_mismatch, client=client
    )

    async with transport:
        pass

    assert client.is_closed is False
    await client.aclose()


async def test_base_transport_closes_owned_client(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    plain_transport = _build_plain_transport()
    transport = plain_transport(settings=validate_settings, cookies=validate_cookies_with_domain_mismatch)
    client = transport._client

    async with transport:
        pass

    assert client.is_closed is True


async def test_base_transport_detaches_event_hooks_after_context_exit(
    validate_settings: Settings,
    validate_cookies_with_domain_mismatch: Cookies,
) -> None:
    plain_transport = _build_plain_transport()
    client = httpx.AsyncClient()
    request_hooks_before = len(client.event_hooks["request"])
    response_hooks_before = len(client.event_hooks["response"])

    transport = plain_transport(
        settings=validate_settings, cookies=validate_cookies_with_domain_mismatch, client=client
    )
    assert len(client.event_hooks["request"]) == request_hooks_before + 1
    assert len(client.event_hooks["response"]) == response_hooks_before + 1

    async with transport:
        pass

    assert len(client.event_hooks["request"]) == request_hooks_before
    assert len(client.event_hooks["response"]) == response_hooks_before
    await client.aclose()
