import asyncio
import getpass
import logging
from asyncio import Runner
from collections.abc import Sequence
from typing import Any, cast, override

from InquirerPy import inquirer
from rich.logging import RichHandler

from pyicloud.constants import Endpoints
from pyicloud.exceptions import PyiCloudUserCancelledError
from pyicloud.log import LOGGER as logger
from pyicloud.log.httpx import LoggerHook
from pyicloud.models.settings import Settings
from pyicloud.services import Application, FindMyiPhone
from pyicloud.trees import (
    BehaveTree,
    TreeAction,
    TreeConfig,
    TreeState,
    TreeTransition,
    use_context,
)
from pyicloud.trees.renew import RenewModelTree
from pyicloud.trees.setup import SetupHooks, SetupModelTree

# Mock imports for testing user
from tests.const import REQUIRES_2FA_USER, VALID_2FA_CODE
from tests.mock import PyiCloudMockTransport
from tests.unit.test_account_login import account_login_handler
from tests.unit.test_security_code import security_code_handler
from tests.unit.test_signin import signin_handler
from tests.unit.test_trust import trust_handler
from tests.unit.test_validate import validate_handler

# Set the level for this logger
logger.setLevel(logging.DEBUG)

# Create a handler with the desired setti-ngs
handler = RichHandler(rich_tracebacks=True)

# Set the format for this handler
formatter = logging.Formatter("%(message)s", datefmt="[%X]")
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)


class MySetupHooks(SetupHooks):
    @override
    def get_password(self, username):
        # Provide your implementation here
        return getpass.getpass(f"Enter password for {username}: ")

    @override
    def get_security_code(self, device: Any = None):
        # Provide your implementation here
        return input("Enter security code: ")

    @override
    def get_trusted_device(self, devices):
        # Provide your implementation here
        pass


class MySetupTree(SetupModelTree):
    tree_config = TreeConfig(
        # Mock transport for testing
        client_options={
            "event_hooks": {"response": [LoggerHook.async_log_response_hook]},
        },
    )


class MyRenewTree(RenewModelTree):
    tree_config = TreeConfig(
        # Mock transport for testing
        client_options={
            "event_hooks": {"response": [LoggerHook.async_log_response_hook]},
        },
    )


class MyBehaveTree(BehaveTree):
    @override
    def on_error(
        self,
        transition: TreeTransition,
        result: Sequence[Any],
        err: Exception,
    ) -> tuple[TreeAction, Exception | Any]:
        if isinstance(err, PyiCloudUserCancelledError):
            return TreeAction.EXIT, str(err)
        return super().on_error(transition, result, err)


if __name__ == "__main__":
    username = inquirer.select(  # type: ignore
        message="Please choose your email:",
        choices=[
            REQUIRES_2FA_USER,
            "inean.es@gmail.com",
        ],
    ).execute()

    # Create a settings object
    config: Settings = Settings.create(username=username)

    # Only mock the client for test user
    if username == REQUIRES_2FA_USER:
        tree_config = TreeConfig(
            client_options={
                "transport": PyiCloudMockTransport(
                    routes=[
                        (Endpoints.SIGNIN_INIT, signin_handler),
                        (Endpoints.SIGNIN_COMPLETE, signin_handler),
                        (Endpoints.SECURITY_CODE, security_code_handler),
                        (Endpoints.TRUST, trust_handler),
                        (Endpoints.ACCOUNT_LOGIN, account_login_handler),
                        (Endpoints.VALIDATE, validate_handler),
                    ]
                ),
                "event_hooks": {"response": [LoggerHook.async_log_response_hook]},
            }
        )
        MySetupTree.tree_config.update(tree_config)
        MyRenewTree.tree_config.update(tree_config)

    # 1 Try to login using setup_model directly and then use api
    if username == REQUIRES_2FA_USER and False:
        blackboard = {
            "refresh_signin": True,
        }
        with Runner() as runner:
            # We can pass context and creation runtime with context keyword
            # on with context method as well
            setup_model = MySetupTree(settings=cast(Settings, config), hooks=MySetupHooks(), context=blackboard)
            # sigin
            _ = runner.run(setup_model.signin())
            # security code
            _ = runner.run(setup_model.security_code(security_code=VALID_2FA_CODE))
            # trust
            _ = runner.run(setup_model.trust())
            # account login
            _ = runner.run(setup_model.account_login())
            # Get icloud
            _ = runner.run(setup_model.session_validate())
            # Get api
            api = setup_model.blackboard["api"]

    # 2. Try to login using behave tree and then use api directly
    setup_model = MySetupTree(settings=cast(Settings, config), hooks=MySetupHooks())
    # Transitions are model dependant. It' possible to use
    with MyBehaveTree(transitions=setup_model.transitions) as self:
        # Returns finish state and a result (api)
        api = self.session_validate(
            context={
                "refresh_signin": False,
                "security_code": VALID_2FA_CODE,
            },
        )
        assert all(api)
        assert api[-1] == self.context["api"]

    # 3. Try to login using behave tree and then use api in a state-coroutine
    renew_model = MyRenewTree(setup_model=setup_model, context={"refresh_signin": False})
    with MyBehaveTree(transitions=renew_model.transitions) as self:

        @use_context
        async def show_devices(bhtree, api: Any):
            if config.account.username == REQUIRES_2FA_USER:
                devices: FindMyiPhone = Application(api, settings=cast(Settings, config)).devices
                for coro in asyncio.as_completed(map(lambda device: device.content(), devices)):
                    contents = await coro
                    print("-" * 30)
                    print(f"Name - {contents.get('name')}")
                    print(f"Display Name  - {contents.get('deviceDisplayName')}")
                    print(f"Location      - {contents.get('location')}")
                    print(f"Battery Level - {contents.get('batteryLevel')}")
                    print(f"Battery Status- {contents.get('batteryStatus')}")
                    print(f"Device Class  - {contents.get('deviceClass')}")
                    print(f"Device Model  - {contents.get('deviceModel')}")
                return api

            devices = Application(
                api,
                settings=cast(Settings, renew_model.settings),
                cookies=renew_model.cookies,
            ).devices
            found = 0
            async for device in devices:
                found += 1
                contents = await device.content()
                print("-" * 30)
                print(f"Name - {contents.get('name')}")
                print(f"Display Name  - {contents.get('deviceDisplayName')}")
                print(f"Location      - {contents.get('location')}")
                print(f"Battery Level - {contents.get('batteryLevel')}")
                print(f"Battery Status- {contents.get('batteryStatus')}")
                print(f"Device Class  - {contents.get('deviceClass')}")
                print(f"Device Model  - {contents.get('deviceModel')}")
            if found == 0:
                print("No devices were returned by findme/refreshClient for this account.")

            return api

        # Custom action embedded as transition
        action: Sequence[TreeTransition] = [
            {
                "trigger": "show_devices",
                "source": TreeState.SESSION_ACTIVE,
                "dest": TreeState.SESSION_ACTIVE,
                "action": show_devices,
            },
        ]
        # Runs trasnsitions and returns finish state and a result (api)
        api = self.run(transitions=action)
        assert all(api)
        assert api[-1] == self.context["api"]
