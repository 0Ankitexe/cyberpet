"""Regression tests for ScanScreen restart-after-cancel behavior."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, PropertyMock, patch
import time

from cyberpet.ui.scan_screen import ScanScreen


class _StubStatic:
    def __init__(self) -> None:
        self.value = ""

    def update(self, value: str) -> None:
        self.value = value


class _StubButton:
    def __init__(self, label: str = "") -> None:
        self.disabled = False
        self.label = label


class _StubProgressBar:
    def __init__(self) -> None:
        self.progress = 0

    def update(self, *, progress: int = 0) -> None:
        self.progress = progress


class _StubListView:
    def clear(self) -> None:
        return


class _FakeScanHistory:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.cancelled: list[int] = []
        self._next_id = 0

    def start_scan(self, scan_type: str) -> int:
        self.started.append(scan_type)
        self._next_id += 1
        return self._next_id

    def cancel_scan(
        self,
        scan_run_id: int,
        files_scanned: int = 0,
        threats_found: int = 0,
        duration_seconds: float = 0.0,
    ) -> None:
        _ = (files_scanned, threats_found, duration_seconds)
        self.cancelled.append(scan_run_id)


class ScanScreenRestartTests(unittest.TestCase):
    """Validate restart flows immediately after cancellation."""

    def _widget_map(self) -> dict[str, object]:
        return {
            "#status": _StubStatic(),
            "#files": _StubStatic(),
            "#threats": _StubStatic(),
            "#speed": _StubStatic(),
            "#pbar": _StubProgressBar(),
            "#filelog": _StubStatic(),
            "#theader": _StubStatic(),
            "#threat-list": _StubListView(),
            "#start-btn": _StubButton(label="▶  START SCAN"),
            "#pause-btn": _StubButton(label="⏸  PAUSE"),
            "#cancel-btn": _StubButton(label="■  STOP SCAN"),
            "#back-btn": _StubButton(label="←  BACK"),
        }

    def test_start_after_cancel_disables_hard_timeout(self) -> None:
        screen = ScanScreen(scan_type="quick")
        widgets = self._widget_map()
        app = SimpleNamespace(
            _scan_cancel_requested=True,
            _last_scan_cancel_at=0.0,
            _daemon_scan_paused=False,
        )
        screen.set_interval = lambda *_args, **_kwargs: None  # type: ignore[assignment]
        screen.query_one = lambda selector, *_a, **_k: widgets[selector]  # type: ignore[assignment]

        with (
            patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app),
            patch("cyberpet.ui.scan_screen.append_trigger_command", return_value=None),
        ):
            screen.action_do_start()

        self.assertEqual(screen._await_timeout_seconds, 0.0)
        self.assertTrue(screen._restart_after_cancel_wait)
        self.assertIn("waiting for daemon to finish previous cancel", widgets["#filelog"].value)

    def test_waiting_state_requeues_scan_command_periodically(self) -> None:
        screen = ScanScreen(scan_type="quick")
        widgets = self._widget_map()
        screen._done = False
        screen._scanning = True
        screen._awaiting_daemon_events = True
        screen._restart_after_cancel_wait = True
        screen._await_timeout_seconds = 0.0
        screen._retrigger_interval_seconds = 1.0
        screen._scan_start = time.time() - 5.0
        screen._last_retrigger_at = time.time() - 2.0
        screen._event_queue = __import__("asyncio").Queue()
        screen.query_one = lambda selector, *_a, **_k: widgets[selector]  # type: ignore[assignment]

        app = SimpleNamespace(_stream_connected=True)
        with (
            patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app),
            patch("cyberpet.ui.scan_screen.append_trigger_command") as trigger_mock,
        ):
            screen._poll_events()

        trigger_mock.assert_called_once_with("quick")
        self.assertIn("re-queued", widgets["#filelog"].value)

    def test_recent_cancel_timestamp_enables_restart_wait(self) -> None:
        screen = ScanScreen(scan_type="quick")
        widgets = self._widget_map()
        app = SimpleNamespace(
            _scan_cancel_requested=False,
            _last_scan_cancel_at=time.time(),
            _daemon_scan_paused=False,
        )
        screen.set_interval = lambda *_args, **_kwargs: None  # type: ignore[assignment]
        screen.query_one = lambda selector, *_a, **_k: widgets[selector]  # type: ignore[assignment]

        with (
            patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app),
            patch("cyberpet.ui.scan_screen.append_trigger_command", return_value=None),
        ):
            screen.action_do_start()

        self.assertTrue(screen._restart_after_cancel_wait)
        self.assertEqual(screen._await_timeout_seconds, 0.0)

    def test_stale_cancelled_done_is_ignored_while_waiting_new_start(self) -> None:
        screen = ScanScreen(scan_type="quick")
        screen._done = False
        screen._scanning = True
        screen._awaiting_daemon_events = True
        screen._scan_start = time.time()
        screen._await_timeout_seconds = 60.0
        screen._event_queue = __import__("asyncio").Queue()
        screen._event_queue.put_nowait(("DONE", {"cancelled": True}))
        screen._on_complete = Mock()  # type: ignore[assignment]

        app = SimpleNamespace(_stream_connected=True)
        with patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app):
            screen._poll_events()

        screen._on_complete.assert_not_called()  # type: ignore[attr-defined]

    def test_connected_timeout_requeues_instead_of_failing(self) -> None:
        screen = ScanScreen(scan_type="quick")
        widgets = self._widget_map()
        screen._done = False
        screen._scanning = True
        screen._awaiting_daemon_events = True
        screen._restart_after_cancel_wait = False
        screen._await_timeout_seconds = 0.01
        screen._scan_start = time.time() - 1.0
        screen._event_queue = __import__("asyncio").Queue()
        screen.query_one = lambda selector, *_a, **_k: widgets[selector]  # type: ignore[assignment]

        app = SimpleNamespace(_stream_connected=True)
        with (
            patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app),
            patch("cyberpet.ui.scan_screen.append_trigger_command") as trigger_mock,
            patch.object(screen, "_stop_poll") as stop_poll_mock,
        ):
            screen._poll_events()

        self.assertTrue(screen._scanning)
        self.assertTrue(screen._awaiting_daemon_events)
        trigger_mock.assert_called_once_with("quick")
        stop_poll_mock.assert_not_called()
        self.assertIn("re-queued", widgets["#filelog"].value)

    def test_trigger_failure_marks_run_cancelled(self) -> None:
        screen = ScanScreen(scan_type="quick")
        widgets = self._widget_map()
        history = _FakeScanHistory()
        screen._scan_history = history
        screen.set_interval = lambda *_args, **_kwargs: None  # type: ignore[assignment]
        screen.query_one = lambda selector, *_a, **_k: widgets[selector]  # type: ignore[assignment]

        app = SimpleNamespace(
            _scan_cancel_requested=False,
            _last_scan_cancel_at=0.0,
            _daemon_scan_paused=False,
        )
        with (
            patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app),
            patch("cyberpet.ui.scan_screen.append_trigger_command", side_effect=OSError("boom")),
        ):
            screen.action_do_start()

        self.assertEqual(history.started, ["quick"])
        self.assertEqual(history.cancelled, [1])

    def test_stream_timeout_error_marks_run_cancelled(self) -> None:
        screen = ScanScreen(scan_type="quick")
        widgets = self._widget_map()
        history = _FakeScanHistory()
        screen._scan_history = history
        screen._run_id = 7
        screen._done = False
        screen._scanning = True
        screen._awaiting_daemon_events = True
        screen._restart_after_cancel_wait = False
        screen._await_timeout_seconds = 0.01
        screen._scan_start = time.time() - 1.0
        screen._event_queue = __import__("asyncio").Queue()
        screen.query_one = lambda selector, *_a, **_k: widgets[selector]  # type: ignore[assignment]

        app = SimpleNamespace(_stream_connected=False)
        with patch.object(ScanScreen, "app", new_callable=PropertyMock, return_value=app):
            screen._poll_events()

        self.assertEqual(history.cancelled, [7])
        self.assertIn("ERROR:", widgets["#status"].value)


if __name__ == "__main__":
    unittest.main()
