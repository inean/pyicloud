from __future__ import annotations

from pyicloud.models.bodies import DynamicBodyModel
from pyicloud.models.cookies import CookiesModel
from pyicloud.models.fields import (
    PcsCloudkitType,
    PcsDocumentsType,
    PcsMailType,
    PcsNewsType,
    PcsNotesType,
    PcsPhotosType,
    PcsSafariType,
    PcsSharingType,
    ScntType,
    SessionIdType,
    XAppleClientIdType,
    XAppleDsWebSessionTokenType,
    XAppleWebauthHsaLoginType,
    XAppleWebauthHsaTrustType,
    XAppleWebauthLoginType,
    XAppleWebauthTokenType,
    XAppleWebauthUserType,
    XAppleWebauthValidateType,
    XAppleWebKBType,
)
from pyicloud.models.headers import OAuthHeadersModel


class SessionHeaders(OAuthHeadersModel):
    # Required Headers
    scnt: ScntType
    session_id: SessionIdType


class SessionCookies(CookiesModel):
    client_id: XAppleClientIdType
    # HomeKit?
    webauth_hsa_trust: XAppleWebauthHsaTrustType
    # webauth_hsa_login is emptied on successful login
    webauth_hsa_login: XAppleWebauthHsaLoginType

    # PCS Cookies
    Documents: PcsDocumentsType
    Photos: PcsPhotosType
    Cloudkit: PcsCloudkitType
    Safari: PcsSafariType
    Mail: PcsMailType
    Notes: PcsNotesType
    News: PcsNewsType
    Sharing: PcsSharingType

    # Web Auth
    webauth_login: XAppleWebauthLoginType
    webauth_user: XAppleWebauthUserType
    webauth_token: XAppleWebauthTokenType
    webauth_validate: XAppleWebauthValidateType

    # Kb dynamic cookie
    web_kb: XAppleWebKBType
    # Web Session
    ds_web_session_token: XAppleDsWebSessionTokenType


class SessionBody(DynamicBodyModel): ...
