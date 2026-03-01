"""Regression tests for scan state synchronization in the TUI."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cyberpet.events import Event, EventType
from cyberpet.ui.pet import CyberPetApp


class _DummyScanWidget:
    def __init__(self) -> None:
        self.scan_active = False
        self.scan_percent = 0
        self.files_scanned = 0
        self.threats_found = 0
        self.scan_speed = 0.0
        self.quarantined = 0
        self.last_threat = "none"
        self.scan_duration = 0.0
        self.last_scan = "never"


class _DummyFileLog:
    def __init__(self) -> None:
        self._files: list[str] = []

    def add_file(self, filepath: str) -> None:
        self._files.append(filepath)

    def clear_log(self) -> None:
        self._files.clear()


class _DummyEventLog:
    def __init__(self) -> None:
        self.lines: list[tuple[str, int]] = []

    def add_event(self, line: str, severity: int = 0) -> None:
        self.lines.append((line, severity))


class UIScanStateTests(unittest.TestCase):
    """Validate pause/cancel scan-state transitions in the main TUI."""

    def test_load_persisted_scan_summary_uses_latest_completed_scan(self) -> None:
        app = CyberPetApp()
        history = Mock()
        history.get_last_scan.return_value = {
            "scan_type": "full",
            "status": "complete",
            "files_scanned": 1500,
            "threats_found": 2,
            "duration_seconds": 13.5,
            "started_at": "2026-03-01T10:00:00",
            "completed_at": "2026-03-01T10:00:14",
        }

        with patch("cyberpet.ui.pet.ScanHistory", return_value=history):
            app._load_persisted_scan_summary()

        self.assertEqual(app.pet_state.last_scan_type, "full (completed)")
        self.assertEqual(app.pet_state.last_scan_files_scanned, 1500)
        self.assertEqual(app.pet_state.last_scan_threats_found, 2)
        self.assertAlmostEqual(app.pet_state.last_scan_duration, 13.5, places=2)
        self.assertGreater(app.pet_state.last_scan_time, 0.0)
        history.close.assert_called_once()

    def test_load_persisted_scan_summary_marks_cancelled_scan(self) -> None:
        app = CyberPetApp()
        history = Mock()
        history.get_last_scan.return_value = {
            "scan_type": "quick",
            "status": "cancelled",
            "files_scanned": 42,
            "threats_found": 0,
            "duration_seconds": 4.0,
            "started_at": "2026-03-01T10:05:00",
            "completed_at": "2026-03-01T10:05:04",
        }

        with patch("cyberpet.ui.pet.ScanHistory", return_value=history):
            app._load_persisted_scan_summary()

        self.assertEqual(app.pet_state.last_scan_type, "quick (cancelled)")
        self.assertEqual(app.pet_state.last_scan_files_scanned, 42)
        self.assertEqual(app.pet_state.last_scan_threats_found, 0)
        history.close.assert_called_once()

    def test_load_persisted_scan_summary_parses_legacy_numeric_timestamp(self) -> None:
        app = CyberPetApp()
        history = Mock()
        history.get_last_scan.return_value = {
            "scan_type": "quick",
            "status": "completed",
            "files_scanned": 11,
            "threats_found": 1,
            "duration_seconds": 2.0,
            "started_at": 1700000000.0,
            "completed_at": 1700000005.0,
        }

        with patch("cyberpet.ui.pet.ScanHistory", return_value=history):
            app._load_persisted_scan_summary()

        self.assertEqual(app.pet_state.last_scan_type, "quick (completed)")
        self.assertEqual(app.pet_state.last_scan_files_scanned, 11)
        self.assertEqual(app.pet_state.last_scan_threats_found, 1)
        self.assertEqual(app.pet_state.last_scan_time, 1700000005.0)
        history.close.assert_called_once()

    def test_load_persisted_quarantine_count_reads_db(self) -> None:
        app = CyberPetApp()
        conn = Mock()
        cursor = Mock()
        cursor.fetchone.return_value = (9,)
        conn.execute.return_value = cursor
        cfg = SimpleNamespace(quarantine={"vault_path": "/tmp/cyberpet-vault"})

        with (
            patch("cyberpet.config.Config.load", return_value=cfg),
            patch("os.path.exists", return_value=True),
            patch("sqlite3.connect", return_value=conn),
        ):
            app._load_persisted_quarantine_count()

        self.assertEqual(app.pet_state.files_quarantined, 9)
        conn.close.assert_called_once()

    def test_scan_complete_history_snapshot_updates_state_without_notify(self) -> None:
        app = CyberPetApp()
        scan_widget = _DummyScanWidget()
        event_log = _DummyEventLog()

        def _query_one(selector: str, *_args, **_kwargs):
            if selector == "#scan-panel":
                return scan_widget
            if selector == "#event-log":
                return event_log
            raise AssertionError(f"Unexpected selector: {selector}")

        event = Event(
            type=EventType.SCAN_COMPLETE,
            source="daemon",
            data={
                "scan_type": "quick",
                "cancelled": False,
                "files_scanned": 77,
                "threats_found_count": 2,
                "duration_seconds": 5.5,
                "completed_at": "2026-03-01T12:00:05",
                "history_snapshot": True,
            },
            severity=0,
        )

        with (
            patch.object(app, "query_one", side_effect=_query_one),
            patch.object(app, "_refresh_stats_widget"),
            patch.object(app, "_refresh_scan_widget"),
            patch.object(app, "_update_mood"),
            patch.object(app, "notify") as notify_mock,
        ):
            app._handle_event(event)

        self.assertEqual(app.pet_state.last_scan_type, "quick (completed)")
        self.assertEqual(app.pet_state.last_scan_files_scanned, 77)
        self.assertEqual(app.pet_state.last_scan_threats_found, 2)
        self.assertAlmostEqual(app.pet_state.last_scan_duration, 5.5, places=2)
        self.assertGreater(app.pet_state.last_scan_time, 0.0)
        notify_mock.assert_not_called()

    def test_scan_complete_history_snapshot_accepts_numeric_timestamp(self) -> None:
        app = CyberPetApp()
        scan_widget = _DummyScanWidget()
        event_log = _DummyEventLog()

        def _query_one(selector: str, *_args, **_kwargs):
            if selector == "#scan-panel":
                return scan_widget
            if selector == "#event-log":
                return event_log
            raise AssertionError(f"Unexpected selector: {selector}")

        event = Event(
            type=EventType.SCAN_COMPLETE,
            source="daemon",
            data={
                "scan_type": "full",
                "cancelled": True,
                "files_scanned": 5,
                "threats_found_count": 0,
                "duration_seconds": 1.0,
                "completed_at": 1700000020.0,
                "history_snapshot": True,
            },
            severity=0,
        )

        with (
            patch.object(app, "query_one", side_effect=_query_one),
            patch.object(app, "_refresh_stats_widget"),
            patch.object(app, "_refresh_scan_widget"),
            patch.object(app, "_update_mood"),
            patch.object(app, "notify") as notify_mock,
        ):
            app._handle_event(event)

        self.assertEqual(app.pet_state.last_scan_type, "full (cancelled)")
        self.assertEqual(app.pet_state.last_scan_time, 1700000020.0)
        notify_mock.assert_not_called()

    def test_scan_progress_does_not_clear_paused_flag(self) -> None:
        app = CyberPetApp()
        app._daemon_scan_paused = True

        scan_widget = _DummyScanWidget()
        filelog = _DummyFileLog()
        event_log = _DummyEventLog()

        def _query_one(selector: str, *_args, **_kwargs):
            if selector == "#scan-panel":
                return scan_widget
            if selector == "#scan-filelog":
                return filelog
            if selector == "#event-log":
                return event_log
            raise AssertionError(f"Unexpected selector: {selector}")

        event = Event(
            type=EventType.SCAN_PROGRESS,
            source="scanner",
            data={
                "files_scanned": 3,
                "threats_found_count": 0,
                "percent": 10,
                "current_file": "/tmp/a",
            },
            severity=0,
        )

        with (
            patch.object(app, "query_one", side_effect=_query_one),
            patch.object(app, "_refresh_stats_widget"),
            patch.object(app, "_refresh_scan_widget"),
            patch.object(app, "_update_mood"),
        ):
            app._handle_event(event)

        self.assertTrue(app._daemon_scan_paused)

    def test_refresh_scan_widget_hides_active_state_while_cancel_pending(self) -> None:
        app = CyberPetApp()
        app._daemon_scan_active = True
        app._scan_cancel_requested = True
        scan_widget = _DummyScanWidget()

        with patch.object(app, "query_one", return_value=scan_widget):
            app._refresh_scan_widget()

        self.assertFalse(scan_widget.scan_active)

    def test_cancelled_scan_complete_keeps_cancelled_label(self) -> None:
        app = CyberPetApp()
        scan_widget = _DummyScanWidget()
        event_log = _DummyEventLog()

        def _query_one(selector: str, *_args, **_kwargs):
            if selector == "#scan-panel":
                return scan_widget
            if selector == "#event-log":
                return event_log
            raise AssertionError(f"Unexpected selector: {selector}")

        event = Event(
            type=EventType.SCAN_COMPLETE,
            source="scanner",
            data={
                "scan_type": "quick",
                "cancelled": True,
                "files_scanned": 42,
                "threats_found_count": 1,
            },
            severity=0,
        )

        with (
            patch.object(app, "query_one", side_effect=_query_one),
            patch.object(app, "_refresh_stats_widget"),
            patch.object(app, "_refresh_scan_widget"),
            patch.object(app, "_update_mood"),
            patch.object(app, "notify"),
        ):
            app._handle_event(event)

        self.assertEqual(app.pet_state.last_scan_type, "quick (cancelled)")
        self.assertIn("cancelled", app.pet_state.last_event_message.lower())

    def test_open_scan_menu_uses_menu_when_cancel_is_pending(self) -> None:
        app = CyberPetApp()
        app._daemon_scan_active = True
        app._scan_cancel_requested = True
        push_screen = Mock()

        with patch.object(app, "push_screen", push_screen):
            app.action_open_scan_menu()

        self.assertTrue(push_screen.called)
        args, kwargs = push_screen.call_args
        self.assertEqual(args[0].__class__.__name__, "ScanMenuModal")
        self.assertIn("callback", kwargs)


if __name__ == "__main__":
    unittest.main()
