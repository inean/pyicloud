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
LOGIN_REQUEST_COOKIES = [DSLANG, SITE]

LOGIN_AASP = Cookie(
    header="Set-Cookie",
    value="aasp=login_aasp; path=/; domain=idmsa.apple.com; path_spec;" " secure; discard; HttpOnly; version=0",
)

ACN01 = Cookie(
    header="Set-Cookie",
    value="acn01=acn01_value; path=/; domain=.apple.com; path_spec; secure; "
    "expires=2099-03-01 16:44:10Z; HttpOnly; version=0",
)

X_APPLE_UNIQUE_CLIENT_ID = Cookie(
    header="Set-Cookie",
    value="X-APPLE-UNIQUE-CLIENT-ID=clientId_value; path=/; path_spec; " "domain_dot; secure; discard; version=0",
)

X_APPLE_WEBAUTH_LOGIN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-LOGIN=v=1:webauth_login_value; path=/;  path_spec; "
    "domain_dot; secure; discard; HttpOnly=None; version=0",
)

X_APPLE_WEBAUTH_VALIDATE = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-VALIDATE=v=1:webauth_login_value; path=/;  "
    "path_spec; domain_dot; secure; discard; version=0",
)

X_APPLE_WEBAUTH_HSA_LOGIN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-HSA-LOGIN=v=2:webauth_login_value; path=/;  path_spec; "
    "domain_dot; secure; discard; HttpOnly=None; version=0",
)

X_APPLE_WEBAUTH_USER = Cookie(
    header="Set-Cookie",
    value="X-APPLE-WEBAUTH-USER=v=1:s=1:d=webauth_user_value; path=/;  "
    "path_spec; domain_dot; secure; expires=2024-03-31 16:44:10Z; HttpOnly=None; version=0",
)

X_APPLE_DS_WEB_SESSION_TOKEN = Cookie(
    header="Set-Cookie",
    value="X-APPLE-DS-WEB-SESSION-TOKEN=session_token; path=/;  path_spec; "
    "domain_dot; secure; expires=2029-03-31 16:44:10Z; HttpOnly=None; version=0",
)
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
