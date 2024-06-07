# fmt: off

class Endpoints:
    HOME = "https://www.icloud.com"
    INIT = "https://setup.icloud.com/setup/ws/1"
    AUTH = "https://idmsa.apple.com/appleauth/auth"

    # Auth Setup Endpoints
    SIGNIN = "https://idmsa.apple.com/appleauth/auth/signin"
    SECURITY_CODE ="https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"
    TRUST = "https://idmsa.apple.com/appleauth/auth/2sv/trust"

    # Account Endpoints
    ACCOUNT_LOGIN = "https://setup.icloud.com/setup/ws/1/accountLogin"


class AppleHeaders:
    # Account Headers
    COUNTRY_CODE             = "x-apple-id-account-country"
    SESSION_ID               = "x-apple-id-session-id"
    # Session Headers
    REQUEST_ID               = "x-apple-i-request-id"
    SESSION_TOKEN            = "x-apple-session-token"
    WIDGET_KEY               = "x-apple-widget-key"
    TRUST_TOKEN              = "x-apple-twosv-trust-token"
    TRUST_TOKEN_ELIGIBLE     = "x-apple-twosv-trust-eligible"
    AUTH_ATTRIBUTES          = "x-apple-auth-attributes"
    SCNT                     = "scnt"
    # Oauth Headers
    OAUTH_CLIENT_ID          = "x-apple-oauth-client-id"
    OAUTH_CLIENT_TYPE        = "x-apple-oauth-client-type"
    OAUTH_REDIRECT_URI       = "x-apple-oauth-redirect-uri"
    OAUTH_REQUIRE_GRANT_CODE = "x-apple-oauth-require-grant-code"
    OAUTH_GRANT_CODE         = "x-apple-oauth-grant-code"
    OAUTH_RESPONSE_TYPE      = "x-apple-oauth-response-type"
    OAUTH_RESPONSE_MODE      = "x-apple-oauth-response-mode"
    OAUTH_STATE              = "x-apple-oauth-state"

class AppleCookies:
    # User Cookies
    DSLANG            = "dslang"
    SITE              = "site"

    # Session Cookies
    AASP              = "aasp"
    ACN01             = "acn01"
    WEB_SESSION_TOKEN = "X-APPLE-DS-WEB-SESSION-TOKEN"
    CLIENT_ID         = "X-APPLE-UNIQUE-CLIENT-ID"
    WEBAUTH_LOGIN     = "X-APPLE-WEBAUTH-LOGIN"
    WEBAUTH_USER      = "X-APPLE-WEBAUTH-USER"
    WEBAUTH_VALIDATE  = "X-APPLE-WEBAUTH-VALIDATE"
    WEBAUTH_HSA_LOGIN = "X-APPLE-WEBAUTH-HSA-LOGIN"
    WEBAUTH_FMIP      = "X-APPLE-WEBAUTH-FMIP"
    WEBAUTH_HSA_TRUST = "X-APPLE-WEBAUTH-HSA-TRUST"
    WEBAUTH_TOKEN     = "X-APPLE-WEBAUTH-TOKEN"

    # Secret Cookies
    DES_PATTERN       = r"DES\w+"

class iCloud:
    CLIENT_TYPE = "firstPartyAuth"
    REDIRECT_URI = Endpoints.HOME
    REQUIRE_GRANT_CODE = "true"
    RESPONSE_MODE = "web_message"
    RESPONSE_TYPE = "code"
    WIDGET_KEY =  "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"

ISO_639_1_CODES = [
    'AA', 'AB', 'AE', 'AF', 'AK', 'AM', 'AN', 'AR', 'AS', 'AV', 'AY', 'AZ', 'BA', 'BE',
    'BG', 'BH', 'BI', 'BM', 'BN', 'BO', 'BR', 'BS', 'CA', 'CE', 'CH', 'CO', 'CR', 'CS',
    'CU', 'CV', 'CY', 'DA', 'DE', 'DV', 'DZ', 'EE', 'EL', 'EN', 'EO', 'ES', 'ET', 'EU',
    'FA', 'FF', 'FI', 'FJ', 'FO', 'FR', 'FY', 'GA', 'GD', 'GL', 'GN', 'GU', 'GV', 'HA',
    'HE', 'HI', 'HO', 'HR', 'HT', 'HU', 'HY', 'HZ', 'IA', 'ID', 'IE', 'IG', 'II', 'IK',
    'IO', 'IS', 'IT', 'IU', 'JA', 'JV', 'KA', 'KG', 'KI', 'KJ', 'KK', 'KL', 'KM', 'KN',
    'KO', 'KR', 'KS', 'KU', 'KV', 'KW', 'KY', 'LA', 'LB', 'LG', 'LI', 'LN', 'LO', 'LT',
    'LU', 'LV', 'MG', 'MH', 'MI', 'MK', 'ML', 'MN', 'MR', 'MS', 'MT', 'MY', 'NA', 'NB',
    'ND', 'NE', 'NG', 'NL', 'NN', 'NO', 'NR', 'NV', 'NY', 'OC', 'OJ', 'OM', 'OR', 'OS',
    'PA', 'PI', 'PL', 'PS', 'PT', 'QU', 'RM', 'RN', 'RO', 'RU', 'RW', 'SA', 'SC', 'SD',
    'SE', 'SG', 'SI', 'SK', 'SL', 'SM', 'SN', 'SO', 'SQ', 'SR', 'SS', 'ST', 'SU', 'SV',
    'SW', 'TA', 'TE', 'TG', 'TH', 'TI', 'TK', 'TL', 'TN', 'TO', 'TR', 'TS', 'TT', 'TW',
    'TY', 'UG', 'UK', 'UR', 'UZ', 'VE', 'VI', 'VO', 'WA', 'WO', 'XH', 'YI', 'YO', 'ZA',
    'ZH', 'ZU'
]

ISO_3166_1_CODES =[
    'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW',
    'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN',
    'BO', 'BQ', 'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG',
    'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ',
    'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI',
    'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL',
    'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR',
    'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM',
    'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA',
    'LB', 'LC', 'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME',
    'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU',
    'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP',
    'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR',
    'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC', 'SD',
    'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV',
    'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO',
    'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE',
    'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'XK', 'YE', 'YT', 'ZA', 'ZM', 'ZW'
]

ISO_3166_1_CODES_3 = [
    'AND', 'ARE', 'AFG', 'ATG', 'AIA', 'ALB', 'ARM', 'AGO', 'ATA', 'ARG', 'ASM', 'AUT',
    'AUS', 'ABW', 'ALA', 'AZE', 'BIH', 'BRB', 'BGD', 'BEL', 'BFA', 'BGR', 'BHR', 'BDI',
    'BEN', 'BLM', 'BMU', 'BRN', 'BOL', 'BES', 'BRA', 'BHS', 'BTN', 'BVT', 'BWA', 'BLR',
    'BLZ', 'CAN', 'CCK', 'COD', 'CAF', 'COG', 'CHE', 'CIV', 'COK', 'CHL', 'CMR', 'CHN',
    'COL', 'CRI', 'CUB', 'CPV', 'CUW', 'CXR', 'CYP', 'CZE', 'DEU', 'DJI', 'DNK', 'DMA',
    'DOM', 'DZA', 'ECU', 'EST', 'EGY', 'ESH', 'ERI', 'ESP', 'ETH', 'FIN', 'FJI', 'FLK',
    'FSM', 'FRO', 'FRA', 'GAB', 'GBR', 'GRD', 'GEO', 'GUF', 'GGY', 'GHA', 'GIB', 'GRL',
    'GMB', 'GIN', 'GLP', 'GNQ', 'GRC', 'SGS', 'GTM', 'GUM', 'GNB', 'GUY', 'HKG', 'HMD',
    'HND', 'HRV', 'HTI', 'HUN', 'IDN', 'IRL', 'ISR', 'IMN', 'IND', 'IOT', 'IRQ', 'IRN',
    'ISL', 'ITA', 'JEY', 'JAM', 'JOR', 'JPN', 'KEN', 'KGZ', 'KHM', 'KIR', 'COM', 'KNA',
    'PRK', 'KOR', 'KWT', 'CYM', 'KAZ', 'LAO', 'LBN', 'LCA', 'LIE', 'LKA', 'LBR', 'LSO',
    'LTU', 'LUX', 'LVA', 'LBY', 'MAR', 'MCO', 'MDA', 'MNE', 'MAF', 'MDG', 'MHL', 'MKD',
    'MLI', 'MMR', 'MNG', 'MAC', 'MNP', 'MTQ', 'MRT', 'MSR', 'MLT', 'MUS', 'MDV', 'MWI',
    'MEX', 'MYS', 'MOZ', 'NAM', 'NCL', 'NER', 'NFK', 'NGA', 'NIC', 'NLD', 'NOR', 'NPL',
    'NRU', 'NIU', 'NZL', 'OMN', 'PAN', 'PER', 'PYF', 'PNG', 'PHL', 'PAK', 'POL', 'SPM',
    'PCN', 'PRI', 'PSE', 'PRT', 'PLW', 'PRY', 'QAT', 'REU', 'ROU', 'SRB', 'RUS', 'RWA',
    'SAU', 'SLB', 'SYC', 'SDN', 'SWE', 'SGP', 'SHN', 'SVN', 'SJM', 'SVK', 'SLE', 'SMR',
    'SEN', 'SOM', 'SUR', 'SSD', 'STP', 'SLV', 'SXM', 'SYR', 'SWZ', 'TCA', 'TCD', 'ATF',
    'TGO', 'THA', 'TJK', 'TKL', 'TLS', 'TKM', 'TUN', 'TON', 'TUR', 'TTO', 'TUV', 'TWN',
    'TZA', 'UKR', 'UGA', 'UMI', 'USA', 'URY', 'UZB', 'VAT', 'VCT', 'VEN', 'VGB', 'VIR',
    'VNM', 'VUT', 'WLF', 'WSM', 'XKX', 'YEM', 'MYT', 'ZAF', 'ZMB', 'ZWE'
]

# fmt: on
