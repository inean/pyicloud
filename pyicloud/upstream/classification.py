"""Classify upstream HTTP requests into stable step and service labels."""

from __future__ import annotations

from urllib.parse import urlparse


def classify_upstream_request(*, method: str, url: str) -> tuple[str, str]:
    """Return (target_service, step) labels for one upstream request."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    clean_method = method.strip().upper()
    lower_path = path.lower()

    if host == "idmsa.apple.com":
        target_service = "apple.idmsa"
        if lower_path.endswith("/signin/init") and clean_method == "POST":
            return target_service, "signin"
        if lower_path.endswith("/signin/complete") and clean_method == "POST":
            return target_service, "signin"
        if lower_path.endswith("/verify/trusteddevice/securitycode") and clean_method == "POST":
            return target_service, "security_code"
        if lower_path.endswith("/2sv/trust") and clean_method == "GET":
            return target_service, "trust"
        return target_service, "auth_request"

    if host == "setup.icloud.com":
        target_service = "apple.setup"
        if lower_path.endswith("/accountlogin") and clean_method == "POST":
            return target_service, "account_login"
        if lower_path.endswith("/validate") and clean_method == "POST":
            return target_service, "validate"
        if "/device/getdevices" in lower_path and clean_method == "GET":
            return target_service, "account_devices"
        if "/family/getfamilydetails" in lower_path and clean_method == "GET":
            return target_service, "account_family"
        if lower_path.endswith("/storageusageinfo") and clean_method == "GET":
            return target_service, "account_storage"
        return target_service, "setup_request"

    if "fmip" in host or "findmy" in host or "fmi" in lower_path:
        return "apple.findmy", "find_devices"

    if "icloud-content.com" in host:
        return "apple.content", "content_download"

    if "icloud.com" in host:
        if "drivews" in lower_path:
            return "apple.drive", "drive_request"
        if "ckdatabase" in lower_path:
            return "apple.photos", "photos_request"
        if "ubiquity" in lower_path:
            return "apple.ubiquity", "ubiquity_request"

    return "apple.unknown", "unknown"
