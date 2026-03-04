#! /usr/bin/env python
"""
A Command Line Wrapper to allow easy use of pyicloud for
command line scripts, and related.
"""

from __future__ import annotations

import logging
import pickle
import sys

import asyncclick as click

from pyicloud.adapters.auth import authenticate_legacy_endpoint
from pyicloud.cli_auth import run_bootstrap_auth
from pyicloud.bootstrap import build_service_endpoint_restore
from pyicloud.services import PyiCloudServices

DEVICE_ERROR = "Please use the --device switch to indicate which device to use."


def create_pickled_data(idevice, filename):
    """
    This helper will output the idevice to a pickled file named
    after the passed filename.

    This allows the data to be used without resorting to screen / pipe
    scrapping.
    """
    with open(filename, "wb") as pickle_file:
        pickle.dump(idevice.content, pickle_file, protocol=pickle.HIGHEST_PROTOCOL)


class _DictProxy:
    __slots__ = ("_dict", "_default")

    def __init__(self, d, default=None):
        object.__setattr__(self, "_dict", d)
        object.__setattr__(self, "_default", default)

    def __getattr__(self, name):
        return self._dict.get(name, self._default)


async def _legacy_authenticate(username: str, password: str, *, interactive: bool):
    return await authenticate_legacy_endpoint(
        username=username,
        password=password,
        interactive=interactive,
    )


def _bootstrap_endpoint(username: str, password: str):
    restore = build_service_endpoint_restore()
    return restore.restore(
        account_id=username,
        password=password,
    )


@click.command(name="icloud", help="Find My iPhone CommandLine Tool")
@click.option("-u", "--username", required=True, help="Apple ID to Use")
@click.option("-p", "--password", default="", help="Apple ID Password to Use")
@click.option("--non-interactive", "interactive", is_flag=True, default=True, help="Disable interactive prompts.")
@click.option("--locate", is_flag=True, default=False, help="Retrieve Location for the iDevice (non-exclusive).")
@click.option("--device", "device_id", default=False, help="Only effect this device")
@click.option("--sound", is_flag=True, default=False, help="Play a sound on the device")
@click.option("--message", default=False, help="Optional Text Message to display with a sound")
@click.option("--silentmessage", default=False, help="Optional Text Message to display with no sounds")
@click.option("--lostmode", is_flag=True, default=False, help="Enable Lost mode for the device")
@click.option("--lostphone", "lost_phone", default=False, help="Phone Number allowed to call when lost mode is enabled")
@click.option("--lostpassword", "lost_password", default=False, help="Forcibly active this passcode on the idevice")
@click.option("--lostmessage", "lost_message", default="", help="Forcibly display this message when activating lost mode.")
@click.option("-v", "verbose", count=True, help="Increase output verbosity")
@click.option(
    "--auth-engine",
    type=click.Choice(["legacy", "bootstrap"]),
    default="legacy",
    show_default=True,
    help="Authentication backend to use.",
)
@click.option("--auth-only", is_flag=True, default=False, help="Authenticate and exit without device actions.")
@click.option(
    "--list", "list", is_flag=True, default=False, help="Short Listings for Device(s) associated with account"
)
@click.option(
    "--llist", "longlist", is_flag=True, default=False, help="Detailed Listings for Device(s) associated with account"
)
@click.option(
    "--outputfile",
    "output_to_file",
    is_flag=True,
    default=False,
    help="Save device data to a file in the current directory.",
)
async def main(**kwargs):
    """Main commandline entrypoint."""

    command_line = _DictProxy(kwargs)

    match command_line.verbose:
        case 2 if command_line.verbose >= 2:
            logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        case 1:
            logging.basicConfig(stream=sys.stderr, level=logging.INFO)
        case _:
            logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

    username = str.strip(command_line.username)
    password = str.strip(command_line.password)
    endpoint = None

    if command_line.auth_engine == "bootstrap":
        await run_bootstrap_auth(
            username=username,
            password=password,
            interactive=command_line.interactive,
        )
        if command_line.auth_only:
            return
        endpoint = _bootstrap_endpoint(username=username, password=password)

    if command_line.auth_only:
        return

    if endpoint is None:
        endpoint = await _legacy_authenticate(
            username=username,
            password=password,
            interactive=command_line.interactive,
        )

    for dev in PyiCloudServices(endpoint=endpoint).devices:
        if not command_line.device_id or (command_line.device_id.strip().lower() == dev.content["id"].strip().lower()):
            # List device(s)
            if command_line.locate:
                dev.location()

            if command_line.output_to_file:
                create_pickled_data(
                    dev,
                    filename=(dev.content["name"].strip().lower() + ".fmip_snapshot"),
                )

            contents = dev.content
            if command_line.longlist:
                print("-" * 30)
                print(contents["name"])
                for key in contents:
                    print("%20s - %s" % (key, contents[key]))
            elif command_line.list:
                print("-" * 30)
                print("Name - %s" % contents["name"])
                print("Display Name  - %s" % contents["deviceDisplayName"])
                print("Location      - %s" % contents["location"])
                print("Battery Level - %s" % contents["batteryLevel"])
                print("Battery Status- %s" % contents["batteryStatus"])
                print("Device Class  - %s" % contents["deviceClass"])
                print("Device Model  - %s" % contents["deviceModel"])

            # Play a Sound on a device
            if command_line.sound:
                if command_line.device_id:
                    dev.play_sound()
                else:
                    raise RuntimeError(
                        "\n\n\t\t%s %s\n\n"
                        % (
                            "Sounds can only be played on a singular device.",
                            DEVICE_ERROR,
                        )
                    )

            # Display a Message on the device
            if command_line.message:
                if command_line.device_id:
                    dev.display_message(subject="A Message", message=command_line.message, sounds=True)
                else:
                    raise RuntimeError(
                        "%s %s"
                        % (
                            "Messages can only be played on a singular device.",
                            DEVICE_ERROR,
                        )
                    )

            # Display a Silent Message on the device
            if command_line.silentmessage:
                if command_line.device_id:
                    dev.display_message(
                        subject="A Silent Message",
                        message=command_line.silentmessage,
                        sounds=False,
                    )
                else:
                    raise RuntimeError(
                        "%s %s"
                        % (
                            "Silent Messages can only be played " "on a singular device.",
                            DEVICE_ERROR,
                        )
                    )

            # Enable Lost mode
            if command_line.lostmode:
                if command_line.device_id:
                    dev.lost_device(
                        number=command_line.lost_phone.strip(),
                        text=command_line.lost_message.strip(),
                        newpasscode=command_line.lost_password.strip(),
                    )
                else:
                    raise RuntimeError(
                        "%s %s"
                        % (
                            "Lost Mode can only be activated on a singular device.",
                            DEVICE_ERROR,
                        )
                    )
    sys.exit(0)


if __name__ == "__main__":
    main()
