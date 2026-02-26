"""Unit tests for fanotify file monitor decision logic."""

from __future__ import annotations

import unittest

from cyberpet.ebpf.file_monitor import FAN_ALLOW, FAN_DENY, FileAccessMonitor
from cyberpet.events import EventBus, EventType


class FileMonitorPolicyTests(unittest.TestCase):
    """Validate block/suspicious policy matching logic."""

    def setUp(self) -> None:
        self.monitor = FileAccessMonitor(EventBus(), monitored_paths=[], whitelist=[])

    def test_tmp_process_denied_for_sensitive_file(self) -> None:
        decision, _reason, event_type, severity = self.monitor._evaluate_access(
            process_name="evil",
            process_path="/tmp/evil",
            target_path="/etc/passwd",
            write_access=False,
        )
        self.assertEqual(decision, FAN_DENY)
        self.assertEqual(event_type, EventType.FILE_ACCESS_BLOCKED)
        self.assertGreaterEqual(severity, 80)

    def test_python_shadow_access_is_denied(self) -> None:
        decision, _reason, event_type, _severity = self.monitor._evaluate_access(
            process_name="python3",
            process_path="/usr/bin/python3",
            target_path="/etc/shadow",
            write_access=False,
        )
        self.assertEqual(decision, FAN_DENY)
        self.assertEqual(event_type, EventType.FILE_ACCESS_BLOCKED)

    def test_non_package_manager_write_to_bin_is_denied(self) -> None:
        decision, _reason, event_type, _severity = self.monitor._evaluate_access(
            process_name="custom-installer",
            process_path="/usr/local/bin/custom-installer",
            target_path="/bin/ls",
            write_access=True,
        )
        self.assertEqual(decision, FAN_DENY)
        self.assertEqual(event_type, EventType.FILE_ACCESS_BLOCKED)

    def test_non_sudo_process_sudoers_access_is_denied(self) -> None:
        decision, _reason, event_type, _severity = self.monitor._evaluate_access(
            process_name="nano",
            process_path="/usr/bin/nano",
            target_path="/etc/sudoers",
            write_access=False,
        )
        self.assertEqual(decision, FAN_DENY)
        self.assertEqual(event_type, EventType.FILE_ACCESS_BLOCKED)

    def test_temp_process_etc_access_can_be_flagged_without_block(self) -> None:
        decision, _reason, event_type, severity = self.monitor._evaluate_access(
            process_name="tmp-proc",
            process_path="/tmp/tmp-proc",
            target_path="/etc/hosts",
            write_access=False,
        )
        self.assertEqual(decision, FAN_ALLOW)
        self.assertEqual(event_type, EventType.FILE_ACCESS_SUSPICIOUS)
        self.assertGreaterEqual(severity, 30)


if __name__ == "__main__":
    unittest.main()
