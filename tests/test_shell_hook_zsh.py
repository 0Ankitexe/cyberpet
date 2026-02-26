"""Integration checks for shell hook behavior in zsh."""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest

from cyberpet.config import Config
from cyberpet.events import EventBus
from cyberpet.terminal_guard import TerminalGuard

TEST_SHELL = shutil.which("zsh") or shutil.which("bash")


@unittest.skipUnless(TEST_SHELL, "A POSIX shell (zsh/bash) is required for shell hook integration tests")
class ShellHookIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Validate shell hook checks with live socket responses."""

    async def asyncSetUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self._tmpdir.name, "guard.sock")
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.shell_bin = TEST_SHELL

        self.config = Config(
            {
                "general": {
                    "pet_name": "Byte",
                    "event_stream_socket": os.path.join(self._tmpdir.name, "events.sock"),
                },
                "terminal_guard": {
                    "enabled": True,
                    "socket_path": self.socket_path,
                    "socket_mode": "0660",
                    "socket_group": "",
                    "block_threshold": 61,
                    "hard_block_threshold": 86,
                    "allow_override_phrase": "CYBERPET ALLOW",
                },
                "ui": {
                    "refresh_rate_ms": 500,
                    "pet_name": "Byte",
                },
            }
        )
        self.guard = TerminalGuard(self.config, EventBus())
        await self.guard.start()

    async def asyncTearDown(self) -> None:
        await self.guard.stop()
        self._tmpdir.cleanup()

    async def _run_shell(self, script: str, stdin_data: str = "") -> tuple[int, str, str]:
        """Run a shell script and return (rc, stdout, stderr)."""
        env = os.environ.copy()
        env["CYBERPET_SOCKET"] = self.socket_path
        env["CYBERPET_CLIENT"] = os.path.join(self.repo_root, "scripts", "socket_client.py")
        env["CYBERPET_ENABLED"] = "true"
        env.pop("_CYBERPET_HOOK_LOADED", None)

        proc = await asyncio.create_subprocess_exec(
            self.shell_bin,
            "-c",
            script,
            cwd=self.repo_root,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await proc.communicate(stdin_data.encode("utf-8"))
        return proc.returncode, out_b.decode("utf-8", errors="replace"), err_b.decode("utf-8", errors="replace")

    async def test_shell_allows_safe_command(self) -> None:
        """Shell hook should allow safe commands."""
        script = (
            "source scripts/shell_hook.sh; "
            "_cyberpet_check_command 'ls -la'; "
            "printf 'rc:%s\\n' \"$?\""
        )
        rc, out, _err = await self._run_shell(script)
        self.assertEqual(rc, 0)
        self.assertIn("rc:0", out)

    async def test_shell_blocks_wrong_override(self) -> None:
        """Shell hook must reject wrong override phrase."""
        script = (
            "source scripts/shell_hook.sh; "
            "_cyberpet_check_command 'rm -rf /'; "
            "printf 'rc:%s\\n' \"$?\""
        )
        rc, out, _err = await self._run_shell(script, stdin_data="wrong phrase\n")
        self.assertEqual(rc, 0)
        self.assertIn("rc:1", out)

    async def test_shell_allows_correct_override(self) -> None:
        """Shell hook should allow command with exact override phrase."""
        script = (
            "source scripts/shell_hook.sh; "
            "_cyberpet_check_command 'rm -rf /'; "
            "printf 'rc:%s\\n' \"$?\""
        )
        rc, out, _err = await self._run_shell(script, stdin_data="CYBERPET ALLOW\n")
        self.assertEqual(rc, 0)
        self.assertIn("rc:0", out)

    async def test_shell_blocks_when_override_times_out(self) -> None:
        """Blocked prompt should time out and keep command blocked."""
        script = (
            "export CYBERPET_OVERRIDE_TIMEOUT=0; "
            "source scripts/shell_hook.sh; "
            "_cyberpet_check_command 'rm -rf /'; "
            "printf 'rc:%s\\n' \"$?\""
        )
        rc, out, err = await self._run_shell(script, stdin_data="")
        self.assertEqual(rc, 0)
        self.assertIn("rc:1", out)
        self.assertTrue(
            "Override timed out. Command blocked." in err
            or "Command cancelled." in err
        )


if __name__ == "__main__":
    unittest.main()
