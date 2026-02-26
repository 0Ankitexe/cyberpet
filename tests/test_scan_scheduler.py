"""Unit tests for V2 scan scheduler behavior."""

from __future__ import annotations

import asyncio
import os
import tempfile
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


if __name__ == "__main__":
    unittest.main()
