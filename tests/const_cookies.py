from collections import namedtuple

Cookie = namedtuple("Cookie", ["header", "value"])

DSLANG = Cookie(
    header="Set-Cookie",
    value="dslang=US-EN; path=/; domain=.apple.com; path_spec; secure; discard; HttpOnly; version=0",
)

SITE = Cookie(
    header="Set-Cookie",
    value="site=USA; path=/; domain=.apple.com; path_spec; secure; discard; HttpOnly; version=0",
)

LOGIN_AASP = Cookie(
    header="Set-Cookie",
    value="aasp=login_aasp; path=/; domain=idmsa.apple.com; path_spec; secure; discard; HttpOnly; version=0",
)

ACN01 = Cookie(
    header="Set-Cookie",
    value="acn01=acn01_value; path=/; domain=.apple.com; path_spec; secure; " "HttpOnly; version=0",
)

X_APPLE_UNIQUE_CLIENT_ID = Cookie(
    header="Set-Cookie",
    value="X-APPLE-UNIQUE-CLIENT-ID=clientId_value; path=/; path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_LOGIN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-LOGIN=v=1:webauth_login_value; path=/;  path_spec; secure; discard; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_VALIDATE = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-VALIDATE=v=1:webauth_login_value; path=/;  path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_HSA_LOGIN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-HSA-LOGIN=webauth_login_value; path=/;  path_spec; secure; discard; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_USER = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-USER=webauth_user_value; path=/; path_spec; secure; expires=2024-03-31; "
    "HttpOnly; version=0",
)
X_APPLE_WEBAUTH_FMIP = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-FMIP=webauth_fmip_value; path=/;  "
    "path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_HSA_TRUST = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-HSA-TRUST=webauth_hsa_trust_value; path=/;  "
    "path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_TOKEN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-TOKEN=v=webauth_token_value; path=/;  "
    "path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

X_APPLE_DS_WEB_SESSION_TOKEN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-DS-WEB-SESSION-TOKEN=session_token; path=/;  path_spec; "
    "secure; expires=2029-03-31; HttpOnly; version=0",
)

BASE_COOKIES: list[Cookie] = [DSLANG, SITE]
LOGIN_COOKIES: list[Cookie] = [LOGIN_AASP]

LOGGED_COOKIES: list[Cookie] = [
    ACN01,
    X_APPLE_DS_WEB_SESSION_TOKEN,
    X_APPLE_UNIQUE_CLIENT_ID,
    X_APPLE_WEBAUTH_LOGIN,
    X_APPLE_WEBAUTH_USER,
    X_APPLE_WEBAUTH_VALIDATE,
    *BASE_COOKIES,
    *LOGIN_COOKIES,
]
VERIFY_COOKIES: list[Cookie] = [
    X_APPLE_WEBAUTH_HSA_LOGIN,
    *LOGGED_COOKIES,
]
VERIFIED_COOKIES: list[Cookie] = [
    X_APPLE_WEBAUTH_HSA_TRUST,
    X_APPLE_WEBAUTH_FMIP,
    X_APPLE_WEBAUTH_TOKEN,
    *BASE_COOKIES,
    *LOGGED_COOKIES,
]


LOGIN_RESPONSE_COOKIES = [
    DSLANG,
    SITE,
    X_APPLE_UNIQUE_CLIENT_ID,
    LOGIN_AASP,
    ACN01,
    X_APPLE_WEBAUTH_LOGIN,
    X_APPLE_WEBAUTH_VALIDATE,
    X_APPLE_WEBAUTH_HSA_LOGIN,
    X_APPLE_WEBAUTH_USER,
    X_APPLE_DS_WEB_SESSION_TOKEN,
]
