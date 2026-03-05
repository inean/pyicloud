from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Sequence, Type, override

import httpx
import srp
from pydantic import ConfigDict, Field

from pyicloud.constants import AppleHeaders as Header
from pyicloud.constants import Endpoints
from pyicloud.models.bodies import BodyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    AaspType,
    AcceptType,
    Acn01Type,
    AuthAttributesType,
    ContentTypeType,
    CountryCodeType,
    DslangCookieType,
    Meta,
    OriginType,
    RequestIdType,
    ScntType,
    SessionIdType,
    SessionTokenType,
    SiteCookieType,
    TrustTokenEligibleType,
    TrustTokensType,
    UsernameType,
)
from pyicloud.models.headers import HeadersModel, OAuthHeadersModel
from pyicloud.sessions import (
    BaseRequest,
    BaseResponse,
    OAuthTransport,
    RequestConfig,
    ResponseConfig,
    StaticEndpoint,
    serialize,
)


class _SrpPassword:
    def __init__(self, password: str):
        self.password = password
        self.salt: bytes | None = None
        self.iterations: int | None = None
        self.key_length = 32

    def set_encrypt_info(self, *, salt: bytes, iterations: int, key_length: int = 32) -> None:
        self.salt = salt
        self.iterations = iterations
        self.key_length = key_length

    def encode(self) -> bytes:
        if self.salt is None or self.iterations is None:
            raise ValueError("SRP salt/iterations are not initialized")
        password_hash = hashlib.sha256(self.password.encode("utf-8")).digest()
        return hashlib.pbkdf2_hmac("sha256", password_hash, self.salt, self.iterations, self.key_length)


@dataclass(slots=True)
class _SrpInitState:
    account_name: str
    challenge: str
    salt: bytes
    server_public: bytes
    iterations: int
    request_id: str | None = None


class _SrpSigninFlow:
    def __init__(self, *, username: str, password: str, settings: Any, cookies: Any) -> None:
        srp.rfc5054_enable()
        srp.no_username_in_x()
        self._settings = settings
        self._cookies = cookies
        self._srp_password = _SrpPassword(password)
        self._user = srp.User(username, self._srp_password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        self._account_name = username

    @classmethod
    def from_settings(cls, settings: Any, cookies: Any) -> _SrpSigninFlow:
        if not (password := settings.account.password):
            raise ValueError("Password is required for SRP signin flow.")
        password_value = password.get_secret_value()
        if not password_value:
            raise ValueError("Password is required for SRP signin flow.")
        return cls(
            username=settings.account.username,
            password=password_value,
            settings=settings,
            cookies=cookies,
        )

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.b64encode(value).decode()

    @staticmethod
    def _b64decode(value: str) -> bytes:
        return base64.b64decode(value)

    @staticmethod
    def sanitize_headers(headers: httpx.Headers) -> httpx.Headers:
        headers = httpx.Headers(headers)
        headers.pop("content-length", None)
        headers.pop("cookie", None)
        return headers

    @staticmethod
    def normalize_account_name(account_name: str | bytes) -> str:
        if isinstance(account_name, bytes):
            return account_name.decode()
        return str(account_name)

    def build_init_payload(self) -> dict[str, Any]:
        account_name, public_a = self._user.start_authentication()
        self._account_name = self.normalize_account_name(account_name)
        return {
            "a": self._b64encode(public_a),
            "accountName": self._account_name,
            "protocols": ["s2k", "s2k_fo"],
        }

    def parse_init_response(self, init_response: httpx.Response) -> _SrpInitState:
        try:
            parsed_init = SignInInitResponse.model_validate(
                {},
                context={
                    "response": init_response,
                    "settings": self._settings,
                    "cookies": self._cookies,
                },
            )
            body = parsed_init.body
            assert body is not None
            state = _SrpInitState(
                account_name=self._account_name,
                challenge=body.srp_challenge,
                salt=self._b64decode(body.salt),
                server_public=self._b64decode(body.server_public),
                iterations=int(body.iteration),
                request_id=init_response.headers.get(Header.REQUEST_ID),
            )
        except (AssertionError, KeyError, ValueError, TypeError) as err:
            raise ValueError("Invalid SRP init response.") from err

        # Persist init phase session state before completing signin.
        self._cookies.model_validate_from_response(parsed_init)
        self._settings.model_validate_from_response(parsed_init)
        return state

    def build_complete_payload(self, state: _SrpInitState) -> dict[str, Any]:
        self._srp_password.set_encrypt_info(salt=state.salt, iterations=state.iterations, key_length=32)
        m1 = self._user.process_challenge(state.salt, state.server_public)
        m2 = self._user.H_AMK
        if m1 is None or m2 is None:
            raise ValueError("Could not generate SRP challenge response.")

        payload: dict[str, Any] = {
            "accountName": state.account_name,
            "c": state.challenge,
            "m1": self._b64encode(m1),
            "m2": self._b64encode(m2),
            "rememberMe": True,
            "trustTokens": [],
        }
        if trust_token := self._settings.token.trust:
            payload["trustTokens"] = [trust_token]
        return payload

##
# SignIn Facade Request
##
class SignInEndpoint(StaticEndpoint):
    endpoint = Endpoints.SIGNIN_INIT
    verb = "POST"
    content_type = "application/json"


class SignInRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"


class SignInRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType


class SignInRequestBody(BodyModel):
    account_name: UsernameType
    trust_tokens: TrustTokensType = None
    remember_me: Annotated[bool, Meta(body="rememberMe")] = True


class SignInRequest(
    BaseRequest[
        SignInRequestHeaders,
        SignInRequestCookies,
        SignInRequestBody,
        SignInEndpoint,
    ]
):
    _config = RequestConfig(
        headers=SignInRequestHeaders,
        cookies=SignInRequestCookies,
        body=SignInRequestBody,
        endpoint=SignInEndpoint,
    )


##
# SignIn Init
##
class SignInInitEndpoint(StaticEndpoint):
    endpoint = Endpoints.SIGNIN_INIT
    verb = "POST"
    content_type = "application/json"


class SignInInitRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"


class SignInInitRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType


class SignInInitRequestBody(BodyModel):
    a: str
    account_name: UsernameType
    protocols: list[str] = Field(default_factory=lambda: ["s2k", "s2k_fo"])


class SignInInitRequest(
    BaseRequest[
        SignInInitRequestHeaders,
        SignInInitRequestCookies,
        SignInInitRequestBody,
        SignInInitEndpoint,
    ]
):
    _config = RequestConfig(
        headers=SignInInitRequestHeaders,
        cookies=SignInInitRequestCookies,
        body=SignInInitRequestBody,
        endpoint=SignInInitEndpoint,
    )


class SignInInitResponseHeaders(HeadersModel):
    request_id: RequestIdType
    scnt: ScntType
    session_id: SessionIdType | None = None


class SignInInitResponseCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    aasp: AaspType | None = None


class SignInInitResponseBody(BodyModel):
    model_config = ConfigDict(extra="allow")

    iteration: int
    salt: str
    protocol: str | None = None
    server_public: str = Field(alias="b")
    srp_challenge: str = Field(alias="c")


class SignInInitResponse(
    BaseResponse[
        SignInInitResponseHeaders,
        SignInInitResponseCookies,
        SignInInitResponseBody,
    ]
):
    _config = ResponseConfig(
        headers=SignInInitResponseHeaders,
        cookies=SignInInitResponseCookies,
        body=SignInInitResponseBody,
    )


@serialize
class SignInInit(OAuthTransport[SignInInitRequest, SignInInitResponse]):
    @property
    def response_cls(self) -> Type[SignInInitResponse]:
        return SignInInitResponse

    @property
    def request_cls(self) -> Type[SignInInitRequest]:
        return SignInInitRequest


##
# SignIn Complete
##
class SignInCompleteEndpoint(StaticEndpoint):
    endpoint = Endpoints.SIGNIN_COMPLETE
    verb = "POST"
    content_type = "application/json"

    remember_me: Annotated[bool, Meta(params="isRememberMeEnabled")] = True


class SignInCompleteRequestHeaders(OAuthHeadersModel):
    accept: AcceptType = "application/json"
    origin: OriginType = Endpoints.HOME
    content_type: ContentTypeType = "application/json"

    scnt: ScntType
    session_id: SessionIdType


class SignInCompleteRequestCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType


class SignInCompleteRequestBody(BodyModel):
    account_name: UsernameType
    srp_challenge: str = Field(alias="c")
    m1: str
    m2: str
    remember_me: Annotated[bool, Meta(body="rememberMe")] = True
    trust_tokens: TrustTokensType = None


class SignInCompleteRequest(
    BaseRequest[
        SignInCompleteRequestHeaders,
        SignInCompleteRequestCookies,
        SignInCompleteRequestBody,
        SignInCompleteEndpoint,
    ]
):
    _config = RequestConfig(
        headers=SignInCompleteRequestHeaders,
        cookies=SignInCompleteRequestCookies,
        body=SignInCompleteRequestBody,
        endpoint=SignInCompleteEndpoint,
    )


class SignInCompleteResponseHeaders(HeadersModel):
    request_id: RequestIdType
    scnt: ScntType

    country_code: CountryCodeType | None = None
    session_id: SessionIdType | None = None
    session_token: SessionTokenType | None = None

    trust_token_eligible: TrustTokenEligibleType | None = None
    auth_attributes: AuthAttributesType | None = None


class SignInCompleteResponseCookies(CookiesModel):
    dslang: DslangCookieType
    site: SiteCookieType
    acn01: Acn01Type | None = None
    aasp: AaspType | None = None


class SignInCompleteResponseBody(BodyModel):
    model_config = ConfigDict(extra="allow")

    auth_type: Literal["hsa2"] | None = Field(alias="authType", default=None)


class SignInCompleteResponse(
    BaseResponse[
        SignInCompleteResponseHeaders,
        SignInCompleteResponseCookies,
        SignInCompleteResponseBody,
    ]
):
    _config = ResponseConfig(
        headers=SignInCompleteResponseHeaders,
        cookies=SignInCompleteResponseCookies,
        body=SignInCompleteResponseBody,
    )

    @override
    @classmethod
    def is_error(cls, status_code):
        """Treat 409 authType=hsa2 as successful primary auth phase."""
        return False if status_code == 409 else super().is_error(status_code)


@serialize
class SignInComplete(OAuthTransport[SignInCompleteRequest, SignInCompleteResponse]):
    @property
    def response_cls(self) -> Type[SignInCompleteResponse]:
        return SignInCompleteResponse

    @property
    def request_cls(self) -> Type[SignInCompleteRequest]:
        return SignInCompleteRequest


# Backward-compat alias for existing imports/tests.
SignInResponse = SignInCompleteResponse


##
# SignIn Orchestrator
##
@serialize
class SignIn(OAuthTransport[SignInRequest, SignInCompleteResponse]):
    @property
    def response_cls(self) -> Type[SignInCompleteResponse]:
        return SignInCompleteResponse

    @property
    def request_cls(self) -> Type[SignInRequest]:
        return SignInRequest

    async def send_signin(self, client: httpx.AsyncClient | None = None) -> SignInCompleteResponse:
        client = client or self._client
        await self._send_srp_signin(client)
        return self.response

    @override
    async def send_request(self, client: httpx.AsyncClient | None = None) -> httpx.Response:
        client = client or self._client
        await self._send_srp_signin(client)
        assert self._response is not None, "No response available"
        return self._response

    async def _send_srp_signin(self, client: httpx.AsyncClient) -> None:
        flow = _SrpSigninFlow.from_settings(self._settings, self._cookies)
        request_cookies = self.dump_cookies(include=["dslang", "site"], exclude_unset=True, exclude_defaults=False)
        client.cookies.update(request_cookies)

        init_headers = self.dump_headers()
        if scnt := self._settings.client_settings.scnt:
            init_headers[Header.SCNT] = scnt
        if session_id := self._settings.account.session_id:
            init_headers[Header.SESSION_ID] = session_id
        init_headers = _SrpSigninFlow.sanitize_headers(init_headers)

        init_payload = flow.build_init_payload()

        init_response = await client.post(
            Endpoints.SIGNIN_INIT,
            json=init_payload,
            headers=init_headers,
        )

        if init_response.is_error:
            return

        state = flow.parse_init_response(init_response)
        complete_payload = flow.build_complete_payload(state)

        complete_headers = self.dump_headers()
        complete_headers = _SrpSigninFlow.sanitize_headers(complete_headers)
        if state.request_id:
            complete_headers[Header.REQUEST_ID] = state.request_id

        await client.post(
            Endpoints.SIGNIN_COMPLETE,
            params={"isRememberMeEnabled": "true"},
            json=complete_payload,
            headers=complete_headers,
        )


@serialize
class FreshSignIn(SignIn):
    """Re-login to iCloud using available session data."""

    @override
    def dump_headers(
        self,
        headers: httpx.Headers | None = None,
        *,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset=True,
        exclude_defaults=False,
        context: Any = None,
    ):
        headers = headers or httpx.Headers()
        headers = super().dump_headers(
            headers,
            include=include,
            exclude=exclude or [Header.COUNTRY_CODE],
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            context=context,
        )

        if scnt := self._settings["client_settings.scnt"]:
            headers[Header.SCNT] = scnt
        if session_id := self._settings["account.session_id"]:
            headers[Header.SESSION_ID] = session_id

        return headers
