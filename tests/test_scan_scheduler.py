"""Unit tests for V2 scan scheduler behavior."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
import unittest
from datetime import datetime
from unittest.mock import patch

from cyberpet.config import Config
from cyberpet.events import EventBus
from cyberpet.scanner import ScanReport
from cyberpet.scan_scheduler import ScanScheduler
from cyberpet.state import PetState


class _FakeHashDatabase:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def bulk_import_from_csv(self, _path: str) -> int:
        return 0

    def close(self) -> None:
        pass


class _FakeYaraEngine:
    available = False

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def compile_rules(self) -> bool:
        return False


class _FakeQuarantineVault:
    def __init__(self, *_args, **_kwargs) -> None:
        self.quarantined: list[str] = []

    async def quarantine_file(self, filepath: str, _threat) -> str:
        self.quarantined.append(filepath)
        return "q-id"

    def close(self) -> None:
        pass


class _FakeScanHistory:
    def __init__(self, *_args, **_kwargs) -> None:
        self.claimed: list[str] = []
        self.completed: list[tuple[int, int, int, float]] = []
        self.cancelled: list[int] = []
        self.closed = False
        self._next_id = 100

    def claim_or_start_scan(self, scan_type: str, max_age_seconds: float = 120.0) -> int:
        _ = max_age_seconds
        self.claimed.append(scan_type)
        self._next_id += 1
        return self._next_id

    def complete_scan(
        self,
        scan_run_id: int,
        files_scanned: int = 0,
        threats_found: int = 0,
        duration_seconds: float = 0.0,
    ) -> None:
        self.completed.append((scan_run_id, files_scanned, threats_found, duration_seconds))

    def cancel_scan(
        self,
        scan_run_id: int,
        files_scanned: int = 0,
        threats_found: int = 0,
        duration_seconds: float = 0.0,
    ) -> None:
        _ = (files_scanned, threats_found, duration_seconds)
        self.cancelled.append(scan_run_id)

    def cancel_all_running(self) -> int:
        return 0

    def close(self) -> None:
        self.closed = True


class _BlockingScanner:
    def __init__(self) -> None:
        self.quick_calls = 0
        self.full_calls = 0
        self.full_started = asyncio.Event()
        self.allow_full_finish = asyncio.Event()

    async def quick_scan(self) -> ScanReport:
        self.quick_calls += 1
        now = datetime.now()
        return ScanReport(scan_type="quick", start_time=now, end_time=now)

    async def full_scan(self) -> ScanReport:
        self.full_calls += 1
        self.full_started.set()
        await self.allow_full_finish.wait()
        now = datetime.now()
        return ScanReport(scan_type="full", start_time=now, end_time=now)


class _ControllableScanner:
    def __init__(self) -> None:
        self.quick_calls = 0
        self.full_calls = 0
        self.full_started = asyncio.Event()
        self.loop_ticks = 0

    async def quick_scan(self, **_kwargs) -> ScanReport:
        self.quick_calls += 1
        now = datetime.now()
        return ScanReport(scan_type="quick", start_time=now, end_time=now)

    async def full_scan(self, cancel_token=None, pause_event=None, **_kwargs) -> ScanReport:
        self.full_calls += 1
        self.full_started.set()
        while True:
            if cancel_token is not None and cancel_token.is_cancelled():
                break
            if pause_event is not None:
                await pause_event.wait()
            self.loop_ticks += 1
            await asyncio.sleep(0.01)
        now = datetime.now()
        return ScanReport(scan_type="full", start_time=now, end_time=now)


class ScanSchedulerTests(unittest.IsolatedAsyncioTestCase):
    """Validate scheduler date math and queue semantics."""

    def _build_config(self, root: str) -> Config:
        return Config(
            {
                "general": {
                    "pet_name": "Byte",
                    "event_stream_socket": os.path.join(root, "events.sock"),
                },
                "terminal_guard": {
                    "enabled": False,
                    "socket_path": os.path.join(root, "guard.sock"),
                    "block_threshold": 61,
                    "hard_block_threshold": 86,
                    "allow_override_phrase": "CYBERPET ALLOW",
                },
                "ui": {"refresh_rate_ms": 500, "pet_name": "Byte"},
                "scanner": {
                    "quick_scan_interval_minutes": 30,
                    "full_scan_time": "03:00",
                    "max_file_size_mb": 50,
                    "auto_quarantine": False,
                    "auto_quarantine_threshold": 80,
                },
                "file_monitor": {"enabled": False, "monitored_paths": [], "whitelist": []},
                "exec_monitor": {"enabled": False},
                "yara": {"rules_dir": root, "scan_timeout_seconds": 30},
                "quarantine": {"vault_path": os.path.join(root, "quarantine")},
                "hash_db": {"db_path": os.path.join(root, "hashes.db"), "seed_file": ""},
            }
        )

    async def test_next_full_scan_time_handles_month_rollover(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _BlockingScanner()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                seconds = scheduler._seconds_until_next_full_scan(
                    datetime(2026, 1, 31, 23, 50, 0)
                )
                self.assertGreater(seconds, 3 * 3600)
                self.assertLess(seconds, 3 * 3600 + 20 * 60)

    async def test_quick_scan_is_queued_while_full_scan_is_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _BlockingScanner()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True

                full_task = asyncio.create_task(scheduler._run_full_scan())
                await scanner.full_started.wait()

                await scheduler._run_quick_scan()
                self.assertTrue(scheduler._pending_quick)

                scanner.allow_full_finish.set()
                await full_task

                self.assertEqual(scanner.full_calls, 1)
                self.assertEqual(scanner.quick_calls, 1)

    async def test_cancel_clears_pending_queue_and_prevents_auto_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _ControllableScanner()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True

                full_task = asyncio.create_task(scheduler._run_full_scan())
                await scanner.full_started.wait()

                await scheduler._run_quick_scan()
                self.assertTrue(scheduler._pending_quick)

                await scheduler._handle_trigger_command("cancel")
                await asyncio.wait_for(full_task, timeout=3.0)

                self.assertEqual(scanner.full_calls, 1)
                self.assertEqual(scanner.quick_calls, 0)
                self.assertFalse(scheduler._pending_quick)
                self.assertFalse(scheduler._pending_full)
                self.assertFalse(scheduler._scanning)

    async def test_pause_and_resume_toggle_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _ControllableScanner()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True

                full_task = asyncio.create_task(scheduler._run_full_scan())
                await scanner.full_started.wait()

                await asyncio.sleep(0.05)
                before_pause = scanner.loop_ticks
                await scheduler._handle_trigger_command("pause")
                self.assertTrue(scheduler._paused)
                self.assertFalse(scheduler._ensure_pause_event().is_set())

                await asyncio.sleep(0.07)
                during_pause = scanner.loop_ticks
                self.assertLessEqual(during_pause - before_pause, 1)

                await scheduler._handle_trigger_command("resume")
                self.assertFalse(scheduler._paused)
                self.assertTrue(scheduler._ensure_pause_event().is_set())

                await asyncio.sleep(0.07)
                after_resume = scanner.loop_ticks
                self.assertGreater(after_resume, during_pause)

                await scheduler._handle_trigger_command("cancel")
                await asyncio.wait_for(full_task, timeout=3.0)

    async def test_manual_trigger_bypasses_recent_scan_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _ControllableScanner()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True
                scheduler._last_scan_completed = time.time()

                await scheduler._handle_trigger_command("quick")
                await asyncio.sleep(0.1)

                self.assertEqual(scanner.quick_calls, 1)

    async def test_trigger_file_queue_handles_cancel_then_quick(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _ControllableScanner()
            trigger_file = os.path.join(tmpdir, "scan.trigger")
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
                patch("cyberpet.scan_scheduler.TRIGGER_FILE", trigger_file),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True

                full_task = asyncio.create_task(scheduler._run_full_scan())
                await scanner.full_started.wait()

                watch_task = asyncio.create_task(scheduler._watch_trigger())
                await asyncio.sleep(0.1)

                with open(trigger_file, "a") as f:
                    f.write("cancel\nquick\n")

                await asyncio.wait_for(full_task, timeout=3.0)
                await asyncio.sleep(0.3)

                scheduler._running = False
                watch_task.cancel()
                await asyncio.gather(watch_task, return_exceptions=True)

                self.assertEqual(scanner.full_calls, 1)
                self.assertEqual(scanner.quick_calls, 1)

    async def test_scheduler_persists_completed_quick_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _BlockingScanner()
            history = _FakeScanHistory()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
                patch("cyberpet.scan_scheduler.ScanHistory", return_value=history),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True
                await scheduler._run_quick_scan()

                self.assertEqual(history.claimed, ["quick"])
                self.assertEqual(len(history.completed), 1)
                self.assertEqual(history.cancelled, [])

    async def test_scheduler_persists_cancelled_full_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = self._build_config(tmpdir)
            scanner = _ControllableScanner()
            history = _FakeScanHistory()
            with (
                patch("cyberpet.scan_scheduler.HashDatabase", _FakeHashDatabase),
                patch("cyberpet.scan_scheduler.YaraEngine", _FakeYaraEngine),
                patch("cyberpet.scan_scheduler.QuarantineVault", _FakeQuarantineVault),
                patch("cyberpet.scan_scheduler.FileScanner", return_value=scanner),
                patch("cyberpet.scan_scheduler.ScanHistory", return_value=history),
            ):
                scheduler = ScanScheduler(config, EventBus(), PetState())
                scheduler._running = True

                full_task = asyncio.create_task(scheduler._run_full_scan())
                await scanner.full_started.wait()
                await scheduler._handle_trigger_command("cancel")
                await asyncio.wait_for(full_task, timeout=3.0)

                self.assertEqual(history.claimed, ["full"])
                self.assertEqual(len(history.cancelled), 1)


if __name__ == "__main__":
    unittest.main()
