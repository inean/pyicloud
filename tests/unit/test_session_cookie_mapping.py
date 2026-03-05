from __future__ import annotations

import httpx

from pyicloud.constants import AppleCookies as Jar
from pyicloud.sessions.session import SessionCookies


def test_session_cookies_maps_client_login_and_web_kb_from_cookie_jar():
    cookies = httpx.Cookies(
        {
            Jar.DSLANG: "US-EN",
            Jar.SITE: "USA",
            Jar.CLIENT_ID: "clientId_value",
            Jar.WEBAUTH_LOGIN: "webauth_login_value",
            Jar.WEBAUTH_USER: "webauth_user_value",
            Jar.WEBAUTH_TOKEN: "token_value",
            Jar.WEBAUTH_VALIDATE: "validate_value",
            Jar.WEB_SESSION_TOKEN: "session_token",
            "X_APPLE_WEB_KB-XXXXXX": "1",
        }
    )

    parsed = SessionCookies.model_validate({}, context={"cookies": cookies})

    assert parsed.client_id is not None
    assert parsed.webauth_login is not None
    assert parsed.web_kb is not None
