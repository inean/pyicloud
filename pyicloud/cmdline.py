#! /usr/bin/env python
"""
A Command Line Wrapper to allow easy use of pyicloud for
command line scripts, and related.
"""
from __future__ import annotations

import getpass
import logging
import pickle
import sys
from os import name

import anyio
import asyncclick as click

from pyicloud.base import PyiCloud, PyiCloudServices
from pyicloud.exceptions import PyiCloudFailedLoginException

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
    def __init__(self, dict_obj):
        self._dict = dict_obj

    def __getattr__(self, name):
        try:
            return self._dict[name]
        except KeyError:
            pass
        return getattr(self._dict, name)

    @property
    def mirror(self):
        return self._dict


# fmt: off
@click.command(name="icloud", help="Find My iPhone CommandLine Tool")
@click.option("-u", "--username", required=True, help="Apple ID to Use")
@click.option("-p", "--password", default="", help="Apple ID Password to Use")
@click.option("--non-interactive", "interactive", is_flag=True, default=True, help="Disable interactive prompts.")
@click.option("--list", "list", is_flag=True, default=False, help="Short Listings for Device(s) associated with account")
@click.option("--llist", "longlist", is_flag=True, default=False, help="Detailed Listings for Device(s) associated with account")
@click.option("--locate", is_flag=True, default=False, help="Retrieve Location for the iDevice (non-exclusive).")
@click.option("--device", "device_id", default=False, help="Only effect this device")
@click.option("--sound", is_flag=True, default=False, help="Play a sound on the device")
@click.option("--message", default=False, help="Optional Text Message to display with a sound")
@click.option("--silentmessage", default=False, help="Optional Text Message to display with no sounds")
@click.option("--lostmode", is_flag=True, default=False, help="Enable Lost mode for the device")
@click.option("--lostphone", default=False, help="Phone Number allowed to call when lost mode is enabled")
@click.option("--lostpassword", default=False, help="Forcibly active this passcode on the idevice")
@click.option("--lostmessage", default="", help="Forcibly display this message when activating lost mode.")
@click.option("-v","verbose", count=True, help="Increase output verbosity")
@click.option("--outputfile", "output_to_file", is_flag=True, default=False, help="Save device data to a file in the current directory.")
# fmt: on


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

    failure_count = 0
    api = PyiCloud(username, password or "")
    while True:
        # Which password we use is determined by your username, so we
        # do need to check for this first and separately.
        if not username:
            raise click.ClickException("No username supplied")

        try:
            api.authenticate()

            if api.requires_password:
                if command_line.interactive:
                    api.password = getpass.getpass("Password: ")
                    continue

            if api.requires_2fa:
                # fmt: off
                print(
                    "\nTwo-step authentication required.",
                    "\nPlease enter validation code"
                )
                # fmt: on

                code = input("(string) --> ")
                if not api.validate_2fa_code(code):
                    print("Failed to verify verification code")
                    sys.exit(1)

                print("")

            elif api.requires_2sa:
                # fmt: off
                print(
                    "\nTwo-step authentication required.",
                    "\nYour trusted devices are:"
                )
                # fmt: on

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
                device = int(input("(number) --> "))
                device = devices[device]
                if not api.send_verification_code(device):
                    print("Failed to send verification code")
                    sys.exit(1)

                print("\nPlease enter validation code")
                code = input("(string) --> ")
                if not api.validate_verification_code(device, code):
                    print("Failed to verify verification code")
                    sys.exit(1)

                print("")
            break
        except PyiCloudFailedLoginException as err:
            message = f"Bad username or password for {username}"
            password = None

            if (failure_count := failure_count + 1) >= 1:
                raise RuntimeError(message) from err

            print(message, file=sys.stderr)

    for dev in PyiCloudServices(endpoint=api).devices:
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
    main(_anyio_backend="asyncio")
