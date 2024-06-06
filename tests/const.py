"""Test constants."""

from .const_account_family import APPLE_ID_EMAIL, ICLOUD_ID_EMAIL, PRIMARY_EMAIL

# User related constants
AUTHENTICATED_USER = PRIMARY_EMAIL
REQUIRES_2FA_USER = "requires_2fa_user@example.com"
VALID_USERS = [AUTHENTICATED_USER, REQUIRES_2FA_USER, APPLE_ID_EMAIL, ICLOUD_ID_EMAIL]

# Authentication related constants
AUTH_ATTRIBUTES = "auth_attributes"
CLIENT_ID = "client_id"
INVALID_PASSWORD = "invalid_password"
VALID_PASSWORD = "valid_password"
VALID_COOKIE = "valid_cookie"
OAUTH_GRANT_CODE = "oauth_grant_code"

# Session related constants
INVALID_SESSION_ID = "invalid_session_id"
SESSION_ID = "session_id"
SCNT = "scnt"

# 2FA related constants
REQUIRES_2FA_TOKEN = "requires_2fa_token"
VALID_2FA_CODE = "000000"

# Token related constants
VALID_TOKEN = "valid_token"
VALID_TOKENS = [VALID_TOKEN, REQUIRES_2FA_TOKEN]
INVALID_TOKEN = "invalid_token"

# Other constants
REQUEST_ID = "00000000-0000-1000-8000-000000000000"
