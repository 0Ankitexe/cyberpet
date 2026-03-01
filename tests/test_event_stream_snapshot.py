"""Tests for daemon event-stream scan snapshot hydration."""

from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from cyberpet.daemon import EventStreamServer
from cyberpet.events import EventBus, EventType


class EventStreamSnapshotTests(unittest.TestCase):
    """Validate synthetic SCAN_COMPLETE snapshot payload generation."""

    def test_build_last_scan_snapshot_payload(self) -> None:
        history = Mock()
        history.get_last_scan.return_value = {
            "scan_type": "full",
            "status": "complete",
            "files_scanned": 1200,
            "threats_found": 3,
            "duration_seconds": 12.5,
            "started_at": "2026-03-01T09:00:00",
            "completed_at": "2026-03-01T09:00:13",
        }
        server = EventStreamServer(EventBus())

        with patch("cyberpet.scan_history.ScanHistory", return_value=history):
            payload = server._build_last_scan_snapshot_payload()

        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload["type"], EventType.SCAN_COMPLETE.value)
        self.assertEqual(payload["data"]["scan_type"], "full")
        self.assertFalse(payload["data"]["cancelled"])
        self.assertEqual(payload["data"]["files_scanned"], 1200)
        self.assertEqual(payload["data"]["threats_found_count"], 3)
        self.assertTrue(payload["data"]["history_snapshot"])
        history.close.assert_called_once()

    def test_build_last_scan_snapshot_payload_none_when_empty(self) -> None:
        history = Mock()
        history.get_last_scan.return_value = None
        server = EventStreamServer(EventBus())

        with patch("cyberpet.scan_history.ScanHistory", return_value=history):
            payload = server._build_last_scan_snapshot_payload()

        self.assertIsNone(payload)
        history.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()

