"""Login test constants."""

import re
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import cast

from pyicloud.constants import AppleHeaders as Header
from tests.const import AUTH_ATTRIBUTES, OAUTH_GRANT_CODE, REQUEST_ID, SCNT, SESSION_ID, VALID_TOKEN

from .const_account_family import (
    APPLE_ID_COUNTRY_CODE,
    APPLE_ID_EMAIL,
    FIRST_NAME,
    FULL_NAME,
    ICLOUD_ID_EMAIL,
    LAST_NAME,
    PERSON_ID,
    PRIMARY_EMAIL,
)


class Cookie(Sequence):
    def __init__(self, *, header, content, update_expires: bool = True):
        if update_expires and "expires" in content:
            # Update the 'expires' field with the current date
            expires = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            content = re.sub(r"expires=[^;]*", f"expires={expires}", content)
        self._header: str = header
        self._content: str = content

    def __getitem__(self, index):
        match index:
            case 0:
                return self._header
            case 1:
                return self._content
        raise IndexError("Index out of range")

    def __len__(self):
        return 2

    def __iter__(self):
        yield self.name
        yield self.value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._header!r}, {self._content!r})"

    def items(self) -> tuple[str, str]:
        return self._header, self._content

    @property
    def header(self) -> str:
        return self._header

    @property
    def content(self) -> str:
        return self._content

    @property
    def name(self) -> str:
        return cast(str, self._content).split("=")[0]

    @property
    def value(self) -> str:
        return cast(str, self._content).split(";")[0].split("=")[-1]


DSLANG = Cookie(
    header="Set-Cookie",
    content="dslang=US-EN; path=/; path_spec; secure; discard; version=0",
)

SITE = Cookie(
    header="Set-Cookie",
    content="site=USA; path=/; path_spec; secure; discard; version=0",
)

AASP = Cookie(
    header="Set-Cookie",
    content="aasp=login_aasp; path=/; path_spec; secure; discard; version=0",
)

ACN01 = Cookie(
    header="Set-Cookie",
    content="acn01=acn01_value; path=/; path_spec; secure; version=0",
)

X_APPLE_UNIQUE_CLIENT_ID = Cookie(
    header="Set-Cookie",
    content="X-APPLE-UNIQUE-CLIENT-ID=clientId_value; path=/; path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_LOGIN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-LOGIN=webauth_login_value; path=/; path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_VALIDATE = Cookie(
    header="Set-Cookie",
    content=f"X-APPLE-WEBAUTH-VALIDATE={VALID_TOKEN}; path=/; path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_HSA_LOGIN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-HSA-LOGIN=webauth_login_value; path=/; path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_USER = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-USER=webauth_user_value; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_FMIP = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-FMIP=webauth_fmip_value; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_HSA_TRUST = Cookie(
    header="Set-Cookie",
    content=f"X-APPLE-WEBAUTH-HSA-TRUST={VALID_TOKEN}; path=/; ath_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_TOKEN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-TOKEN=webauth_token_value; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_DS_WEB_SESSION_TOKEN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-DS-WEB-SESSION-TOKEN=session_token; path=/; path_spec; secure; expires=; version=0",
)

DES_COOKIE = Cookie(
    header="Set-Cookie",
    content="DESXXXXXX=1; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_DOCUMENTS = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Documents=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_PHOTOS = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Photos=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_CLOUDKIT = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Cloudkit=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_SAFARI = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Safari=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_MAIL = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Mail=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_NOTES = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Notes=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_NEWS = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-News=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

X_APPLE_WEBAUTH_PCS_SHARING = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-PCS-Sharing=pcs_token; path=/; path_spec; secure; expires=; version=0",
)

WEB_KB_COOKIE = Cookie(
    header="Set-Cookie",
    content="X_APPLE_WEB_KB-XXXXXX=1; path=/; path_spec; secure; expires=; version=0",
)
##
# SignIn
##

# Headers
SIGNIN_REQUEST_HEADERS = []
SIGNIN_RESPONSE_HEADERS_KO = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
}

# Cookies
SIGNIN_REQUEST_COOKIES = [
    DSLANG,
    SITE,
]
SIGNIN_RESPONSE_OK_COOKIES = [
    AASP,
    ACN01,
    DSLANG,
    SITE,
]
SIGNIN_RESPONSE_2FA_COOKIES = SIGNIN_RESPONSE_OK_COOKIES
SIGNIN_RESPONSE_KO_COOKIES = [
    AASP,
    DSLANG,
    SITE,
]

##
# SecurityCode
##

# Headers
SECURITY_CODE_REQUEST_HEADERS = []
SECURITY_CODE_RESPONSE_HEADERS_OK = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
    Header.SESSION_TOKEN: VALID_TOKEN,
    Header.COUNTRY_CODE: APPLE_ID_COUNTRY_CODE,
}
SECURITY_CODE_RESPONSE_HEADERS_KO = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
}

# Cookies
SECURITY_CODE_REQUEST_COOKIES = SIGNIN_RESPONSE_OK_COOKIES
SECURITY_CODE_RESPONSE_COOKIES_OK = [
    AASP,
    ACN01,
    DSLANG,
    SITE,
]
SECURITY_CODE_RESPONSE_COOKIES_KO = [
    AASP,
    ACN01,
    DSLANG,
    SITE,
]
SECURITY_CODE_RESPONSE_KO_COOKIES = SECURITY_CODE_RESPONSE_COOKIES_OK

##
# Trust
##

# Headers
TRUST_REQUEST_HEADERS = {
    Header.SESSION_ID: SESSION_ID,
    Header.SCNT: SCNT,
}
TRUST_RESPONSE_HEADERS_OK = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
    Header.SESSION_TOKEN: VALID_TOKEN,
    Header.COUNTRY_CODE: APPLE_ID_COUNTRY_CODE,
    Header.SESSION_ID: SESSION_ID,
    Header.TRUST_TOKEN: VALID_TOKEN,
    Header.SESSION_TOKEN: VALID_TOKEN,
    Header.AUTH_ATTRIBUTES: AUTH_ATTRIBUTES,
    Header.OAUTH_GRANT_CODE: OAUTH_GRANT_CODE,
    Header.SESSION_TOKEN: VALID_TOKEN,
    Header.COUNTRY_CODE: APPLE_ID_COUNTRY_CODE,
}
TRUST_RESPONSE_HEADERS_KO = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
}

# Cookies
TRUST_REQUEST_COOKIES = SECURITY_CODE_RESPONSE_COOKIES_OK

TRUST_RESPONSE_OK_COOKIES = [
    DES_COOKIE,
    DSLANG,
    SITE,
]
TRUST_RESPONSE_KO_COOKIES = [
    DSLANG,
    SITE,
]
##
# AccountLogin
##

# Headers
ACCOUNT_LOGIN_REQUEST_HEADERS = {
    Header.SESSION_ID: SESSION_ID,
    Header.SCNT: SCNT,
}
ACCOUNT_LOGIN_RESPONSE_HEADERS_KO = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
}
ACCOUNT_LOGIN_RESPONSE_HEADERS_OK = {
    Header.REQUEST_ID: REQUEST_ID,
    Header.SCNT: SCNT,
}
# Cookies
ACCOUNT_LOGIN_REQUEST_COOKIES = [DSLANG, SITE]

ACCOUNT_LOGIN_RESPONSE_COOKIES_OK = [
    X_APPLE_WEBAUTH_HSA_TRUST,
    X_APPLE_WEBAUTH_USER,
    X_APPLE_WEBAUTH_VALIDATE,
    X_APPLE_WEBAUTH_TOKEN,
    X_APPLE_DS_WEB_SESSION_TOKEN,
]
ACCOUNT_LOGIN_RESPONSE_COOKIES_KO = []

##
# Validate
##
VALIDATE_REQUEST_HEADERS = ACCOUNT_LOGIN_REQUEST_HEADERS
VALIDATE_RESPONSE_HEADERS_OK = ACCOUNT_LOGIN_RESPONSE_HEADERS_OK
VALIDATE_RESPONSE_HEADERS_KO = {}

# Cookies
VALIDATE_REQUEST_COOKIES = ACCOUNT_LOGIN_REQUEST_COOKIES + ACCOUNT_LOGIN_RESPONSE_COOKIES_OK
VALIDATE_RESPONSE_COOKIES_OK = ACCOUNT_LOGIN_RESPONSE_COOKIES_OK
VALIDATE_RESPONSE_COOKIES_KO = []

# Data
SIGNIN_RESPONSE_BODY_2FA = {"authType": "hsa2"}
SIGNIN_RESPONSE_BODY_KO_BAD_PASSWORD = {
    "serviceErrors": [
        {
            "code": "-20101",
            "message": "Your Apple ID or password was incorrect.",
            "suppressDismissal": False,
        }
    ]
}

SECURITY_CODE_RESPONSE_BODY_KO_BAD_SECURITY_CODE = {
    "service_errors": [
        {
            "code": "-21669",
            "title": "Incorrect Verification Code",
            "message": "Incorrect verification code.",
            "suppressDismissal": False,
        }
    ],
    "hasError": True,
}

TRUST_RESPONSE_BODY_KO_INVALID_SESSION = {
    "service_errors": [
        {
            "code": "-20528",
            "message": "Invalid session.",
            "suppressDismissal": False,
        }
    ],
    "hasError": True,
}

ACCOUNT_LOGIN_REQUEST_BODY = {
    "dsWebAuthToken": VALID_TOKEN,
    "extended_login": True,
    "trustToken": VALID_TOKEN,
}

SESSION_RESPONSE_BODY_OK = {
    "dsInfo": {
        "lastName": LAST_NAME,
        "iCDPEnabled": False,
        "tantorMigrated": True,
        "dsid": PERSON_ID,
        "hsaEnabled": True,
        "ironcadeMigrated": True,
        "locale": "fr-fr_FR",
        "brZoneConsolidated": False,
        "isManagedAppleID": False,
        "gilligan-invited": "true",
        "appleIdAliases": [APPLE_ID_EMAIL, ICLOUD_ID_EMAIL],
        "hsaVersion": 2,
        "isPaidDeveloper": False,
        "countryCode": APPLE_ID_COUNTRY_CODE,
        "notificationId": "12345678-1234-1234-1234-123456789012" + PERSON_ID,
        "primaryEmailVerified": True,
        "aDsID": "123456-12-12345678-1234-1234-1234-123456789012" + PERSON_ID,
        "locked": False,
        "hasICloudQualifyingDevice": True,
        "primaryEmail": PRIMARY_EMAIL,
        "appleIdEntries": [
            {"isPrimary": True, "type": "EMAIL", "value": PRIMARY_EMAIL},
            {"type": "EMAIL", "value": APPLE_ID_EMAIL},
            {"type": "EMAIL", "value": ICLOUD_ID_EMAIL},
        ],
        "gilligan-enabled": "true",
        "fullName": FULL_NAME,
        "languageCode": "fr-fr",
        "appleId": PRIMARY_EMAIL,
        "firstName": FIRST_NAME,
        "iCloudAppleIdAlias": ICLOUD_ID_EMAIL,
        "notesMigrated": True,
        "hasPaymentInfo": False,
        "pcsDeleted": False,
        "appleIdAlias": APPLE_ID_EMAIL,
        "brMigrated": True,
        "statusCode": 2,
        "familyEligible": True,
    },
    "hasMinimumDeviceForPhotosWeb": True,
    "iCDPEnabled": False,
    "webservices": {
        "reminders": {
            "url": "https://p31-remindersws.icloud.com:443",
            "status": "active",
        },
        "notes": {"url": "https://p38-notesws.icloud.com:443", "status": "active"},
        "mail": {"url": "https://p38-mailws.icloud.com:443", "status": "active"},
        "ckdatabasews": {
            "pcsRequired": True,
            "url": "https://p31-ckdatabasews.icloud.com:443",
            "status": "active",
        },
        "photosupload": {
            "pcsRequired": True,
            "url": "https://p31-uploadphotosws.icloud.com:443",
            "status": "active",
        },
        "photos": {
            "pcsRequired": True,
            "uploadUrl": "https://p31-uploadphotosws.icloud.com:443",
            "url": "https://p31-photosws.icloud.com:443",
            "status": "active",
        },
        "drivews": {
            "pcsRequired": True,
            "url": "https://p31-drivews.icloud.com:443",
            "status": "active",
        },
        "uploadimagews": {
            "url": "https://p31-uploadimagews.icloud.com:443",
            "status": "active",
        },
        "schoolwork": {},
        "cksharews": {"url": "https://p31-ckshare.icloud.com:443", "status": "active"},
        "findme": {"url": "https://p31-fmipweb.icloud.com:443", "status": "active"},
        "ckdeviceservice": {"url": "https://p31-ckdevice.icloud.com:443"},
        "iworkthumbnailws": {
            "url": "https://p31-iworkthumbnailws.icloud.com:443",
            "status": "active",
        },
        "calendar": {
            "url": "https://p31-calendarws.icloud.com:443",
            "status": "active",
        },
        "docws": {
            "pcsRequired": True,
            "url": "https://p31-docws.icloud.com:443",
            "status": "active",
        },
        "settings": {
            "url": "https://p31-settingsws.icloud.com:443",
            "status": "active",
        },
        "ubiquity": {
            "url": "https://p31-ubiquityws.icloud.com:443",
            "status": "active",
        },
        "streams": {"url": "https://p31-streams.icloud.com:443", "status": "active"},
        "keyvalue": {
            "url": "https://p31-keyvalueservice.icloud.com:443",
            "status": "active",
        },
        "archivews": {
            "url": "https://p31-archivews.icloud.com:443",
            "status": "active",
        },
        "push": {"url": "https://p31-pushws.icloud.com:443", "status": "active"},
        "iwmb": {"url": "https://p31-iwmb.icloud.com:443", "status": "active"},
        "iworkexportws": {
            "url": "https://p31-iworkexportws.icloud.com:443",
            "status": "active",
        },
        "geows": {"url": "https://p31-geows.icloud.com:443", "status": "active"},
        "account": {
            "iCloudEnv": {"shortId": "p", "vipSuffix": "prod"},
            "url": "https://p31-setup.icloud.com:443",
            "status": "active",
        },
        "fmf": {"url": "https://p31-fmfweb.icloud.com:443", "status": "active"},
        "contacts": {
            "url": "https://p31-contactsws.icloud.com:443",
            "status": "active",
        },
    },
    "pcsEnabled": True,
    "configBag": {
        "urls": {
            "accountCreateUI": "https://appleid.apple.com/widget/account/?widgetKey="
            + "widget_key"
            + PERSON_ID
            + "#!create",
            "accountLoginUI": "https://idmsa.apple.com/appleauth/auth/signin?widgetKey=" + "widget_key" + PERSON_ID,
            "accountLogin": "https://setup.icloud.com/setup/ws/1/accountLogin",
            "accountRepairUI": "https://appleid.apple.com/widget/account/?widgetKey="
            + "widget_key"
            + PERSON_ID
            + "#!repair",
            "downloadICloudTerms": "https://setup.icloud.com/setup/ws/1/downloadLiteTerms",
            "repairDone": "https://setup.icloud.com/setup/ws/1/repairDone",
            "accountAuthorizeUI": "https://idmsa.apple.com/appleauth/auth/authorize/signin?client_id="
            + "widget_key"
            + PERSON_ID,
            "vettingUrlForEmail": "https://id.apple.com/IDMSEmailVetting/vetShareEmail",
            "accountCreate": "https://setup.icloud.com/setup/ws/1/createLiteAccount",
            "getICloudTerms": "https://setup.icloud.com/setup/ws/1/getTerms",
            "vettingUrlForPhone": "https://id.apple.com/IDMSEmailVetting/vetSharePhone",
        },
        "accountCreateEnabled": "true",
    },
    "hsaTrustedBrowser": True,
    "appsOrder": [
        "mail",
        "contacts",
        "calendar",
        "photos",
        "iclouddrive",
        "notes3",
        "reminders",
        "pages",
        "numbers",
        "keynote",
        "newspublisher",
        "fmf",
        "find",
        "settings",
    ],
    "version": 2,
    "isExtendedLogin": True,
    "pcsServiceIdentitiesIncluded": True,
    "hsaChallengeRequired": False,
    "requestInfo": {"country": "FR", "timeZone": "GMT+1", "region": "IDF"},
    "pcsDeleted": False,
    "iCloudInfo": {"SafariBookmarksHasMigratedToCloudKit": True},
    "apps": {
        "calendar": {},
        "reminders": {},
        "keynote": {"isQualifiedForBeta": True},
        "settings": {"canLaunchWithOneFactor": True},
        "mail": {},
        "numbers": {"isQualifiedForBeta": True},
        "photos": {},
        "pages": {"isQualifiedForBeta": True},
        "notes3": {},
        "find": {"canLaunchWithOneFactor": True},
        "iclouddrive": {},
        "newspublisher": {"isHidden": True},
        "fmf": {},
        "contacts": {},
    },
}
SESSION_RESPONSE_BODY_2FA = {
    "dsInfo": {
        "lastName": LAST_NAME,
        "iCDPEnabled": False,
        "tantorMigrated": True,
        "dsid": PERSON_ID,
        "hsaEnabled": True,
        "ironcadeMigrated": True,
        "locale": "fr-fr_FR",
        "brZoneConsolidated": False,
        "isManagedAppleID": False,
        "gilligan-invited": "true",
        "appleIdAliases": [APPLE_ID_EMAIL, ICLOUD_ID_EMAIL],
        "hsaVersion": 2,
        "isPaidDeveloper": False,
        "countryCode": APPLE_ID_COUNTRY_CODE,
        "notificationId": "12345678-1234-1234-1234-123456789012" + PERSON_ID,
        "primaryEmailVerified": True,
        "aDsID": "123456-12-12345678-1234-1234-1234-123456789012" + PERSON_ID,
        "locked": False,
        "hasICloudQualifyingDevice": True,
        "primaryEmail": PRIMARY_EMAIL,
        "appleIdEntries": [
            {"isPrimary": True, "type": "EMAIL", "value": PRIMARY_EMAIL},
            {"type": "EMAIL", "value": APPLE_ID_EMAIL},
            {"type": "EMAIL", "value": ICLOUD_ID_EMAIL},
        ],
        "gilligan-enabled": "true",
        "fullName": FULL_NAME,
        "languageCode": "fr-fr",
        "appleId": PRIMARY_EMAIL,
        "firstName": FIRST_NAME,
        "iCloudAppleIdAlias": ICLOUD_ID_EMAIL,
        "notesMigrated": True,
        "hasPaymentInfo": True,
        "pcsDeleted": False,
        "appleIdAlias": APPLE_ID_EMAIL,
        "brMigrated": True,
        "statusCode": 2,
        "familyEligible": True,
    },
    "hasMinimumDeviceForPhotosWeb": True,
    "iCDPEnabled": False,
    "webservices": {
        "reminders": {
            "url": "https://p31-remindersws.icloud.com:443",
            "status": "active",
        },
        "notes": {"url": "https://p38-notesws.icloud.com:443", "status": "active"},
        "mail": {"url": "https://p38-mailws.icloud.com:443", "status": "active"},
        "ckdatabasews": {
            "pcsRequired": True,
            "url": "https://p31-ckdatabasews.icloud.com:443",
            "status": "active",
        },
        "photosupload": {
            "pcsRequired": True,
            "url": "https://p31-uploadphotosws.icloud.com:443",
            "status": "active",
        },
        "photos": {
            "pcsRequired": True,
            "uploadUrl": "https://p31-uploadphotosws.icloud.com:443",
            "url": "https://p31-photosws.icloud.com:443",
            "status": "active",
        },
        "drivews": {
            "pcsRequired": True,
            "url": "https://p31-drivews.icloud.com:443",
            "status": "active",
        },
        "uploadimagews": {
            "url": "https://p31-uploadimagews.icloud.com:443",
            "status": "active",
        },
        "schoolwork": {},
        "cksharews": {"url": "https://p31-ckshare.icloud.com:443", "status": "active"},
        "findme": {"url": "https://p31-fmipweb.icloud.com:443", "status": "active"},
        "ckdeviceservice": {"url": "https://p31-ckdevice.icloud.com:443"},
        "iworkthumbnailws": {
            "url": "https://p31-iworkthumbnailws.icloud.com:443",
            "status": "active",
        },
        "calendar": {
            "url": "https://p31-calendarws.icloud.com:443",
            "status": "active",
        },
        "docws": {
            "pcsRequired": True,
            "url": "https://p31-docws.icloud.com:443",
            "status": "active",
        },
        "settings": {
            "url": "https://p31-settingsws.icloud.com:443",
            "status": "active",
        },
        "ubiquity": {
            "url": "https://p31-ubiquityws.icloud.com:443",
            "status": "active",
        },
        "streams": {"url": "https://p31-streams.icloud.com:443", "status": "active"},
        "keyvalue": {
            "url": "https://p31-keyvalueservice.icloud.com:443",
            "status": "active",
        },
        "archivews": {
            "url": "https://p31-archivews.icloud.com:443",
            "status": "active",
        },
        "push": {"url": "https://p31-pushws.icloud.com:443", "status": "active"},
        "iwmb": {"url": "https://p31-iwmb.icloud.com:443", "status": "active"},
        "iworkexportws": {
            "url": "https://p31-iworkexportws.icloud.com:443",
            "status": "active",
        },
        "geows": {"url": "https://p31-geows.icloud.com:443", "status": "active"},
        "account": {
            "iCloudEnv": {"shortId": "p", "vipSuffix": "prod"},
            "url": "https://p31-setup.icloud.com:443",
            "status": "active",
        },
        "fmf": {"url": "https://p31-fmfweb.icloud.com:443", "status": "active"},
        "contacts": {
            "url": "https://p31-contactsws.icloud.com:443",
            "status": "active",
        },
    },
    "pcsEnabled": True,
    "configBag": {
        "urls": {
            "accountCreateUI": "https://appleid.apple.com/widget/account/?widgetKey="
            + "widget_key"
            + PERSON_ID
            + "#!create",
            "accountLoginUI": "https://idmsa.apple.com/appleauth/auth/signin?widgetKey=" + "widget_key" + PERSON_ID,
            "accountLogin": "https://setup.icloud.com/setup/ws/1/accountLogin",
            "accountRepairUI": "https://appleid.apple.com/widget/account/?widgetKey="
            + "widget_key"
            + PERSON_ID
            + "#!repair",
            "downloadICloudTerms": "https://setup.icloud.com/setup/ws/1/downloadLiteTerms",
            "repairDone": "https://setup.icloud.com/setup/ws/1/repairDone",
            "accountAuthorizeUI": "https://idmsa.apple.com/appleauth/auth/authorize/signin?client_id="
            + "widget_key"
            + PERSON_ID,
            "vettingUrlForEmail": "https://id.apple.com/IDMSEmailVetting/vetShareEmail",
            "accountCreate": "https://setup.icloud.com/setup/ws/1/createLiteAccount",
            "getICloudTerms": "https://setup.icloud.com/setup/ws/1/getTerms",
            "vettingUrlForPhone": "https://id.apple.com/IDMSEmailVetting/vetSharePhone",
        },
        "accountCreateEnabled": "true",
    },
    "hsaTrustedBrowser": False,
    "appsOrder": [
        "mail",
        "contacts",
        "calendar",
        "photos",
        "iclouddrive",
        "notes3",
        "reminders",
        "pages",
        "numbers",
        "keynote",
        "newspublisher",
        "fmf",
        "find",
        "settings",
    ],
    "version": 2,
    "isExtendedLogin": True,
    "pcsServiceIdentitiesIncluded": False,
    "hsaChallengeRequired": True,
    "requestInfo": {"country": "FR", "timeZone": "GMT+1", "region": "IDF"},
    "pcsDeleted": False,
    "iCloudInfo": {"SafariBookmarksHasMigratedToCloudKit": True},
    "apps": {
        "calendar": {},
        "reminders": {},
        "keynote": {"isQualifiedForBeta": True},
        "settings": {"canLaunchWithOneFactor": True},
        "mail": {},
        "numbers": {"isQualifiedForBeta": True},
        "photos": {},
        "pages": {"isQualifiedForBeta": True},
        "notes3": {},
        "find": {"canLaunchWithOneFactor": True},
        "iclouddrive": {},
        "newspublisher": {"isHidden": True},
        "fmf": {},
        "contacts": {},
    },
}
ACCOUNT_LOGIN_RESPONSE_BODY_KO_MISSING_APPLE_ID = {
    "success": False,
    "error": "Missing apple_id field",
}
ACCOUNT_LOGIN_RESPONSE_BODY_KO_INVALID_SESSION_TOKEN = {
    "success": False,
    "error": "Invalid Session Token",
}

TRUSTED_DEVICE_1 = {
    "deviceType": "SMS",
    "areaCode": "",
    "phoneNumber": "*******58",
    "deviceId": "1",
}
TRUSTED_DEVICES = {"devices": [TRUSTED_DEVICE_1]}

VERIFICATION_CODE_OK = {"success": True}
VERIFICATION_CODE_KO = {"success": False}
