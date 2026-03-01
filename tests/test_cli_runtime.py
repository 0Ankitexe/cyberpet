"""Runtime interpreter selection tests for CLI entrypoints."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

from cyberpet import cli


class CLIRuntimeTests(unittest.TestCase):
    def test_preferred_python_uses_env_candidate_when_present(self) -> None:
        candidate = "/tmp/cyberpet-venv-python"
        with (
            patch.dict(os.environ, {"CYBERPET_PYTHON": candidate}, clear=False),
            patch("os.path.exists", side_effect=lambda p: p == candidate),
        ):
            self.assertEqual(cli._preferred_python(), candidate)

    def test_preferred_python_falls_back_to_current_executable(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("os.path.exists", return_value=False),
            patch.object(sys, "executable", "/usr/bin/python3"),
        ):
            self.assertEqual(cli._preferred_python(), "/usr/bin/python3")

    def test_maybe_reexec_start_execs_when_interpreter_differs(self) -> None:
        with (
            patch.object(cli, "_preferred_python", return_value="/opt/cyberpet/venv/bin/python"),
            patch.object(sys, "executable", "/usr/bin/python3"),
            patch("os.execv") as execv,
        ):
            cli._maybe_reexec_start(no_reexec=False)

        execv.assert_called_once_with(
            "/opt/cyberpet/venv/bin/python",
            ["/opt/cyberpet/venv/bin/python", "-m", "cyberpet", "start", "--no-reexec"],
        )

    def test_maybe_reexec_start_skips_when_same_interpreter(self) -> None:
        with (
            patch.object(cli, "_preferred_python", return_value="/usr/bin/python3"),
            patch.object(sys, "executable", "/usr/bin/python3"),
            patch("os.execv") as execv,
        ):
            cli._maybe_reexec_start(no_reexec=False)

        execv.assert_not_called()

    def test_maybe_reexec_start_respects_no_reexec_flag(self) -> None:
        with (
            patch.object(cli, "_preferred_python", return_value="/opt/cyberpet/venv/bin/python"),
            patch.object(sys, "executable", "/usr/bin/python3"),
            patch("os.execv") as execv,
        ):
            cli._maybe_reexec_start(no_reexec=True)

        execv.assert_not_called()


if __name__ == "__main__":
    unittest.main()

