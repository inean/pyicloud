"""Login test constants."""

import re
from datetime import datetime, timedelta
from typing import cast

from .const_account_family import (
    APPLE_ID_EMAIL,
    FIRST_NAME,
    FULL_NAME,
    ICLOUD_ID_EMAIL,
    LAST_NAME,
    PRIMARY_EMAIL,
)


class Cookie:
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
        yield self._header
        yield self._content

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._header!r}, {self._content!r})"

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
        return cast(str, self._content).split("=")[1].split(";")[0]


DSLANG = Cookie(
    header="Set-Cookie",
    content="dslang=US-EN; path=/; domain=.apple.com; path_spec; secure; discard; HttpOnly; version=0",
)

SITE = Cookie(
    header="Set-Cookie",
    content="site=USA; path=/; domain=.apple.com; path_spec; secure; discard; HttpOnly; version=0",
)

AASP = Cookie(
    header="Set-Cookie",
    content="aasp=login_aasp; path=/; domain=idmsa.apple.com; path_spec; secure; discard; HttpOnly; version=0",
)

ACN01 = Cookie(
    header="Set-Cookie",
    content="acn01=acn01_value; path=/; domain=.apple.com; path_spec; secure; " "HttpOnly; version=0",
)

X_APPLE_UNIQUE_CLIENT_ID = Cookie(
    header="Set-Cookie",
    content="X-APPLE-UNIQUE-CLIENT-ID=clientId_value; path=/; path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_LOGIN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-LOGIN=v=1:webauth_login_value; path=/;  path_spec; secure; discard; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_VALIDATE = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-VALIDATE=v=1:webauth_login_value; path=/;  path_spec; secure; discard; version=0",
)

X_APPLE_WEBAUTH_HSA_LOGIN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-HSA-LOGIN=webauth_login_value; path=/;  path_spec; secure; discard; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_USER = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-USER=webauth_user_value; path=/; path_spec; secure; expires=2024-03-31; "
    "HttpOnly; version=0",
)
X_APPLE_WEBAUTH_FMIP = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-FMIP=webauth_fmip_value; path=/;  "
    "path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_HSA_TRUST = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-HSA-TRUST=webauth_hsa_trust_value; path=/;  "
    "path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

X_APPLE_WEBAUTH_TOKEN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-WEBAUTH-TOKEN=v=webauth_token_value; path=/;  "
    "path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

X_APPLE_DS_WEB_SESSION_TOKEN = Cookie(
    header="Set-Cookie",
    content="X-APPLE-DS-WEB-SESSION-TOKEN=session_token; path=/;  path_spec; "
    "secure; expires=2029-03-31; HttpOnly; version=0",
)
DES_COOKIE = Cookie(
    header="Set-Cookie",
    content="DESXXXXXX=1; path=/; domain=.idmsa.apple.com; path_spec; secure; expires=2024-03-31; HttpOnly; version=0",
)

BASE_COOKIES: list[Cookie] = [DSLANG, SITE]

SIGNIN_REQUEST_COOKIES = BASE_COOKIES
SIGNIN_RESPONSE_OK_COOKIES = [
    *BASE_COOKIES,
    AASP,
    ACN01,
]
SIGNIN_RESPONSE_KO_COOKIES = [
    *BASE_COOKIES,
    AASP,
]

TRUST_REQUEST_COOKIES = [
    *BASE_COOKIES,
    AASP,
    ACN01,
]
TRUST_RESPONSE_OK_COOKIES = [
    DES_COOKIE,
    *BASE_COOKIES,
]
TRUST_RESPONSE_KO_COOKIES = [*BASE_COOKIES]


LOGIN_COOKIES: list[Cookie] = [AASP]

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
SECURITY_CODE_COOKIES: list[Cookie] = [
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
    AASP,
    ACN01,
    X_APPLE_WEBAUTH_LOGIN,
    X_APPLE_WEBAUTH_VALIDATE,
    X_APPLE_WEBAUTH_HSA_LOGIN,
    X_APPLE_WEBAUTH_USER,
    X_APPLE_DS_WEB_SESSION_TOKEN,
]

PERSON_ID = (FIRST_NAME + LAST_NAME).lower()
NOTIFICATION_ID = "12345678-1234-1234-1234-123456789012" + PERSON_ID
A_DS_ID = "123456-12-12345678-1234-1234-1234-123456789012" + PERSON_ID
WIDGET_KEY = "widget_key" + PERSON_ID

# Data
AUTH_OK = {"authType": "hsa2"}
AUTH_KO_BAD_PASSWORD = {
    "serviceErrors": [
        {
            "code": "-20101",
            "message": "Your Apple ID or password was incorrect.",
            "suppressDismissal": False,
        }
    ]
}
AUTH_KO_BAD_SECURITY_CODE = {
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
TRUST_RESPONSE_INVALID_SESSION = {
    "service_errors": [
        {
            "code": "-20528",
            "message": "Invalid session.",
            "suppressDismissal": False,
        }
    ],
    "hasError": True,
}

LOGIN_WORKING = {
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
        "countryCode": "FRA",
        "notificationId": NOTIFICATION_ID,
        "primaryEmailVerified": True,
        "aDsID": A_DS_ID,
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
            "accountCreateUI": "https://appleid.apple.com/widget/account/?widgetKey=" + WIDGET_KEY + "#!create",
            "accountLoginUI": "https://idmsa.apple.com/appleauth/auth/signin?widgetKey=" + WIDGET_KEY,
            "accountLogin": "https://setup.icloud.com/setup/ws/1/accountLogin",
            "accountRepairUI": "https://appleid.apple.com/widget/account/?widgetKey=" + WIDGET_KEY + "#!repair",
            "downloadICloudTerms": "https://setup.icloud.com/setup/ws/1/downloadLiteTerms",
            "repairDone": "https://setup.icloud.com/setup/ws/1/repairDone",
            "accountAuthorizeUI": "https://idmsa.apple.com/appleauth/auth/authorize/signin?client_id=" + WIDGET_KEY,
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

# Setup data
LOGIN_2FA = {
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
        "countryCode": "FRA",
        "notificationId": NOTIFICATION_ID,
        "primaryEmailVerified": True,
        "aDsID": A_DS_ID,
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
            "accountCreateUI": "https://appleid.apple.com/widget/account/?widgetKey=" + WIDGET_KEY + "#!create",
            "accountLoginUI": "https://idmsa.apple.com/appleauth/auth/signin?widgetKey=" + WIDGET_KEY,
            "accountLogin": "https://setup.icloud.com/setup/ws/1/accountLogin",
            "accountRepairUI": "https://appleid.apple.com/widget/account/?widgetKey=" + WIDGET_KEY + "#!repair",
            "downloadICloudTerms": "https://setup.icloud.com/setup/ws/1/downloadLiteTerms",
            "repairDone": "https://setup.icloud.com/setup/ws/1/repairDone",
            "accountAuthorizeUI": "https://idmsa.apple.com/appleauth/auth/authorize/signin?client_id=" + WIDGET_KEY,
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

TRUSTED_DEVICE_1 = {
    "deviceType": "SMS",
    "areaCode": "",
    "phoneNumber": "*******58",
    "deviceId": "1",
}
TRUSTED_DEVICES = {"devices": [TRUSTED_DEVICE_1]}

VERIFICATION_CODE_OK = {"success": True}
VERIFICATION_CODE_KO = {"success": False}
