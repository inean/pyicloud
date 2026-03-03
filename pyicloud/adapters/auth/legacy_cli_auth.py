"""Legacy interactive CLI auth adapter."""

from __future__ import annotations

import getpass
import sys
from collections.abc import Callable
from typing import Any

import asyncclick as click

from pyicloud.exceptions import PyiCloudFailedLoginException, PyiCloudValidationError
from pyicloud.legacy import PyiCloud


def authenticate_legacy_endpoint(
    *,
    username: str,
    password: str,
    interactive: bool,
    getpass_fn: Callable[[str], str] = getpass.getpass,
    input_fn: Callable[[str], str] = input,
    pyicloud_cls: Callable[..., Any] | None = None,
) -> Any:
    """Authenticate through legacy PyiCloud flow and return the authenticated endpoint."""
    pyicloud_cls = pyicloud_cls or PyiCloud
    failure_count = 0
    try:
        api = pyicloud_cls(username=username, password=password)
    except PyiCloudValidationError as err:
        response = [error.get("msg") for error in err.errors() if error.get("msg")]
        raise ValueError("\n".join(response)) from err

    while True:
        if not username:
            raise click.ClickException("No username supplied")

        try:
            api.authenticate()

            if api.requires_password and interactive:
                api.password = getpass_fn("Password: ")
                continue

            if api.requires_2sa:
                print(
                    "\nTwo-step authentication required.",
                    "\nYour trusted devices are:",
                )

                devices = api.trusted_devices
                for i, device in enumerate(devices):
                    print(
                        "    %s: %s"
                        % (
                            i,
                            device.get("deviceName", "SMS to %s" % device.get("phoneNumber")),
                        )
                    )

                print("\nWhich device would you like to use?")
                device = int(input_fn("(number) --> "))
                device = devices[device]
                if not api.send_verification_code(device):
                    print("Failed to send verification code")
                    sys.exit(1)

                print("\nPlease enter validation code")
                code = input_fn("(string) --> ")
                if not api.validate_verification_code(device, code):
                    print("Failed to verify verification code")
                    sys.exit(1)

                print("")
            elif api.requires_2fa:
                print(
                    "\nTwo-step authentication required.",
                    "\nPlease enter validation code",
                )

                code = input_fn("(string) --> ")
                if not api.validate_2fa_code(code):
                    print("Failed to verify verification code")
                    sys.exit(1)

                print("")

            break
        except PyiCloudFailedLoginException as err:
            message = f"Bad username or password for {username}"
            password = ""

            if (failure_count := failure_count + 1) >= 1:
                raise RuntimeError(message) from err

    return api
