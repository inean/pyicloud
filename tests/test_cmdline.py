"""Cmdline tests."""

from __future__ import annotations

import os
import pickle
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from asyncclick.testing import CliRunner

from pyicloud import cmdline

from .const import AUTHENTICATED_USER, REQUIRES_2FA_USER, VALID_PASSWORD
from .const_findmyiphone import FMI_FAMILY_WORKING
from .mock import ServiceEndpointMock


class TestCmdline(IsolatedAsyncioTestCase):
    """Cmdline test cases."""

    def setUp(self):
        """Set up tests."""
        self.main = cmdline.main

    async def test_no_arg(self):
        """Test no args."""
        runner = CliRunner()

        result = await runner.invoke(self.main)
        assert result.exit_code == 2

        result = await runner.invoke(self.main, args=[])
        assert result.exit_code == 2

    async def test_help(self):
        """Test the help command."""
        runner = CliRunner()

        result = await runner.invoke(self.main, ["--help"])
        assert result.exit_code == 0

    @patch("pyicloud.cmdline.run_bootstrap_auth", new_callable=AsyncMock)
    async def test_auth_only_bootstrap(self, mock_bootstrap):
        runner = CliRunner()

        result = await runner.invoke(
            self.main,
            [
                "--username",
                AUTHENTICATED_USER,
                "--password",
                VALID_PASSWORD,
                "--auth-engine",
                "bootstrap",
                "--auth-only",
            ],
        )

        assert result.exit_code == 0
        mock_bootstrap.assert_awaited_once()

    @patch("pyicloud.cmdline.run_bootstrap_auth", new_callable=AsyncMock)
    async def test_bootstrap_engine_with_device_output(self, mock_bootstrap):
        runner = CliRunner()

        with patch(
            "pyicloud.cmdline._legacy_authenticate",
            new_callable=AsyncMock,
            return_value=ServiceEndpointMock(AUTHENTICATED_USER, VALID_PASSWORD),
        ):
            result = await runner.invoke(
                self.main,
                [
                    "--username",
                    AUTHENTICATED_USER,
                    "--password",
                    VALID_PASSWORD,
                    "--non-interactive",
                    "--auth-engine",
                    "bootstrap",
                    "--outputfile",
                ],
            )

        assert result.exit_code == 0
        mock_bootstrap.assert_awaited_once()

    async def test_bootstrap_engine_prefers_stored_endpoint(self):
        runner = CliRunner()

        with (
            patch("pyicloud.cmdline.run_bootstrap_auth", new_callable=AsyncMock) as mock_bootstrap,
            patch("pyicloud.cmdline.restore_legacy_endpoint_from_store") as mock_restore_endpoint,
            patch("pyicloud.cmdline._legacy_authenticate", new_callable=AsyncMock) as mock_legacy_auth,
            patch("pyicloud.cmdline.PyiCloudServices") as mock_services,
        ):
            endpoint = object()
            mock_restore_endpoint.return_value = endpoint
            mock_services.return_value.devices = []

            result = await runner.invoke(
                self.main,
                [
                    "--username",
                    AUTHENTICATED_USER,
                    "--password",
                    VALID_PASSWORD,
                    "--non-interactive",
                    "--auth-engine",
                    "bootstrap",
                ],
            )

            assert result.exit_code == 0
            mock_bootstrap.assert_awaited_once()
            mock_restore_endpoint.assert_called_once()
            mock_legacy_auth.assert_not_called()
            mock_services.assert_called_once_with(endpoint=endpoint)

    async def test_username(self):
        """Test the username command."""
        # No username supplied
        runner = CliRunner()

        result = await runner.invoke(self.main, ["--username"])
        assert result.exit_code == 2

    async def test_username_password_invalid(self):  # pylint: disable=unused-argument
        """Test username and password commands."""
        # Bad username or password
        runner = CliRunner()

        with patch(
            "pyicloud.cmdline._legacy_authenticate",
            new_callable=AsyncMock,
            side_effect=ValueError("Invalid email address. Got 'invalid_user'"),
        ):
            result = await runner.invoke(self.main, ["--username", "invalid_user"])
        assert "Invalid email address. Got 'invalid_user'" in str(result.exception)

        with patch(
            "pyicloud.cmdline._legacy_authenticate",
            new_callable=AsyncMock,
            side_effect=ValueError("Invalid email address. Got 'invalid_user'"),
        ):
            result = await runner.invoke(self.main, ["--username", "invalid_user", "--password", "invalid_pass"])
        assert "Invalid email address. Got 'invalid_user'" in str(result.exception)

    async def test_username_password_requires_2fa(self):
        """Test username and password commands."""
        runner = CliRunner()

        with patch(
            "pyicloud.cmdline._legacy_authenticate",
            new_callable=AsyncMock,
            return_value=ServiceEndpointMock(REQUIRES_2FA_USER, VALID_PASSWORD),
        ):
            result = await runner.invoke(
                self.main,
                [
                    "--username",
                    REQUIRES_2FA_USER,
                    "--password",
                    VALID_PASSWORD,
                    "--non-interactive",
                ],
            )
        assert result.exit_code == 0

    @patch("pyicloud.paths.AbstractPath.loads")
    async def test_device_outputfile(self, mock_loads):  # pylint: disable=unused-argument
        """Test the outputfile command."""

        # Just ignore result of SettingsFile().loads()
        mock_loads.side_effect = lambda: None
        runner = CliRunner()

        with patch(
            "pyicloud.cmdline._legacy_authenticate",
            new_callable=AsyncMock,
            return_value=ServiceEndpointMock(AUTHENTICATED_USER, VALID_PASSWORD),
        ):
            result = await runner.invoke(
                self.main,
                ["--username", AUTHENTICATED_USER, "--password", VALID_PASSWORD, "--non-interactive", "--outputfile"],
            )
        assert result.exit_code == 0

        devices = FMI_FAMILY_WORKING.get("content")
        if devices:
            for device in devices:
                file_name = device.get("name").strip().lower() + ".fmip_snapshot"

                pickle_file = open(file_name, "rb")
                assert pickle_file

                contents = []
                with pickle_file as opened_file:
                    while True:
                        try:
                            contents.append(pickle.load(opened_file))
                        except EOFError:
                            break
                assert contents == [device]

                pickle_file.close()
                os.remove(file_name)

    async def test_auth_only_legacy(self):
        runner = CliRunner()

        with patch(
            "pyicloud.cmdline._legacy_authenticate",
            new_callable=AsyncMock,
            return_value=ServiceEndpointMock(AUTHENTICATED_USER, VALID_PASSWORD),
        ):
            result = await runner.invoke(
                self.main,
                [
                    "--username",
                    AUTHENTICATED_USER,
                    "--password",
                    VALID_PASSWORD,
                    "--non-interactive",
                    "--auth-only",
                ],
            )
        assert result.exit_code == 0
