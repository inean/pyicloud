from __future__ import annotations

from pyicloud.upstream.classification import classify_upstream_request


def test_classification_maps_auth_steps():
    assert classify_upstream_request(method="POST", url="https://idmsa.apple.com/appleauth/auth/signin/init") == (
        "apple.idmsa",
        "signin",
    )
    assert classify_upstream_request(
        method="POST", url="https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode"
    ) == ("apple.idmsa", "security_code")


def test_classification_maps_setup_steps():
    assert classify_upstream_request(method="POST", url="https://setup.icloud.com/setup/ws/1/accountLogin") == (
        "apple.setup",
        "account_login",
    )
    assert classify_upstream_request(method="POST", url="https://setup.icloud.com/setup/ws/1/validate") == (
        "apple.setup",
        "validate",
    )


def test_classification_maps_find_devices_request():
    target, step = classify_upstream_request(
        method="POST",
        url="https://p44-fmip.icloud.com/fmipservice/client/web/refreshClient",
    )
    assert target == "apple.findmy"
    assert step == "find_devices"
