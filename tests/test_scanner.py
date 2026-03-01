"""Tests for cyberpet.scanner — multi-analysis file scanner."""

import asyncio
import hashlib
import os
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

from cyberpet.config import Config
from cyberpet.events import EventBus
from cyberpet.hash_db import HashDatabase
from cyberpet.scanner import CancellationToken, FileScanner, ScanReport


EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class ScannerTests(unittest.TestCase):
    """Unit tests for FileScanner."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._db_path = os.path.join(self._tmpdir, "test.db")
        self._hash_db = HashDatabase(self._db_path)
        self._hash_db.add_malware(EICAR_SHA256, "EICAR-Test-File", 90)
        self._bus = EventBus()

        # Build minimal config data
        config_data = {
            "general": {"pet_name": "Test", "log_level": "DEBUG", "log_path": self._tmpdir,
                        "pid_file": os.path.join(self._tmpdir, "test.pid"),
                        "event_stream_socket": os.path.join(self._tmpdir, "events.sock"),
                        "event_stream_socket_mode": "0660", "event_stream_socket_group": "cyberpet"},
            "terminal_guard": {"enabled": False, "socket_path": os.path.join(self._tmpdir, "tg.sock"),
                               "socket_mode": "0660", "socket_group": "root", "block_threshold": 61,
                               "hard_block_threshold": 86, "override_max_failures": 3,
                               "allow_override_phrase": "ALLOW"},
            "ui": {"refresh_rate_ms": 500, "pet_name": "Test", "show_allowed_events": False},
            "scanner": {"quick_scan_interval_minutes": 30, "full_scan_time": "03:00",
                        "max_file_size_mb": 50, "auto_quarantine": False, "auto_quarantine_threshold": 80},
            "file_monitor": {"enabled": False, "monitored_paths": [], "whitelist": []},
            "exec_monitor": {"enabled": False},
            "yara": {"rules_dir": self._tmpdir, "scan_timeout_seconds": 30},
            "quarantine": {"vault_path": os.path.join(self._tmpdir, "qvault")},
            "hash_db": {"db_path": self._db_path, "seed_file": ""},
        }
        # Reset singleton
        Config._instance = None
        self._config = Config(config_data)

    def tearDown(self):
        self._hash_db.close()
        Config._instance = None
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_eicar_detected_by_hash(self):
        """Scanner should detect the EICAR test file via hash lookup."""
        eicar_path = os.path.join(self._tmpdir, "eicar_test.com")
        with open(eicar_path, "wb") as f:
            f.write(EICAR_STRING)

        scanner = FileScanner(self._config, self._bus, self._hash_db)
        record = scanner._analyze_file(eicar_path)

        self.assertIsNotNone(record)
        self.assertGreaterEqual(record.threat_score, 80)
        self.assertIn("EICAR", record.threat_reason)

    def test_clean_file_returns_none(self):
        """A file with no threats should return None."""
        clean_path = os.path.join(self._tmpdir, "clean.txt")
        with open(clean_path, "w") as f:
            f.write("Hello, this is a perfectly normal file.")

        scanner = FileScanner(self._config, self._bus, self._hash_db)
        record = scanner._analyze_file(clean_path)

        self.assertIsNone(record)

    def test_empty_file_returns_none(self):
        """An empty file should be skipped."""
        empty_path = os.path.join(self._tmpdir, "empty.txt")
        with open(empty_path, "w") as f:
            pass

        scanner = FileScanner(self._config, self._bus, self._hash_db)
        record = scanner._analyze_file(empty_path)

        self.assertIsNone(record)

    def test_missing_file_returns_none(self):
        """A nonexistent file should return None."""
        scanner = FileScanner(self._config, self._bus, self._hash_db)
        record = scanner._analyze_file("/nonexistent/file.txt")
        self.assertIsNone(record)

    def test_entropy_calculation(self):
        """Shannon entropy should handle various inputs."""
        # All identical bytes = 0 entropy
        self.assertAlmostEqual(FileScanner._shannon_entropy(b"\x00" * 100), 0.0)
        # Random-like data = high entropy
        rnd = bytes(range(256)) * 10
        entropy = FileScanner._shannon_entropy(rnd)
        self.assertGreater(entropy, 7.0)
        # Empty = 0
        self.assertEqual(FileScanner._shannon_entropy(b""), 0.0)

    def test_known_clean_hash_skipped(self):
        """A file whose hash is in the clean DB should return None quickly."""
        clean_path = os.path.join(self._tmpdir, "known_clean.txt")
        content = b"Known clean file content"
        with open(clean_path, "wb") as f:
            f.write(content)
        sha = hashlib.sha256(content).hexdigest()
        self._hash_db.add_clean(sha, clean_path)

        scanner = FileScanner(self._config, self._bus, self._hash_db)
        record = scanner._analyze_file(clean_path)
        self.assertIsNone(record)

class ScannerCancellationTests(unittest.IsolatedAsyncioTestCase):
    """Regression tests for scan cancellation behavior."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        config_data = {
            "general": {"pet_name": "Test", "log_level": "DEBUG", "log_path": self._tmpdir,
                        "pid_file": os.path.join(self._tmpdir, "test.pid"),
                        "event_stream_socket": os.path.join(self._tmpdir, "events.sock"),
                        "event_stream_socket_mode": "0660", "event_stream_socket_group": "cyberpet"},
            "terminal_guard": {"enabled": False, "socket_path": os.path.join(self._tmpdir, "tg.sock"),
                               "socket_mode": "0660", "socket_group": "root", "block_threshold": 61,
                               "hard_block_threshold": 86, "override_max_failures": 3,
                               "allow_override_phrase": "ALLOW"},
            "ui": {"refresh_rate_ms": 500, "pet_name": "Test", "show_allowed_events": False},
            "scanner": {"quick_scan_interval_minutes": 30, "full_scan_time": "03:00",
                        "max_file_size_mb": 50, "auto_quarantine": False, "auto_quarantine_threshold": 80},
            "file_monitor": {"enabled": False, "monitored_paths": [], "whitelist": []},
            "exec_monitor": {"enabled": False},
            "yara": {"rules_dir": self._tmpdir, "scan_timeout_seconds": 30},
            "quarantine": {"vault_path": os.path.join(self._tmpdir, "qvault")},
            "hash_db": {"db_path": os.path.join(self._tmpdir, "hashes.db"), "seed_file": ""},
        }
        Config._instance = None
        self._config = Config(config_data)
        self._bus = EventBus()
        self._scanner = FileScanner(self._config, self._bus, None, None)

    def tearDown(self):
        Config._instance = None
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    async def test_streaming_cancel_does_not_deadlock_on_full_queue(self) -> None:
        token = CancellationToken()
        token.cancel()
        report = ScanReport(scan_type="quick", start_time=datetime.now())

        def _collector():
            for i in range(5000):
                yield f"/tmp/f{i}"

        with patch.object(self._scanner, "_analyze_file", return_value=None):
            await asyncio.wait_for(
                self._scanner._scan_streaming(_collector, report, cancel_token=token),
                timeout=2.0,
            )


if __name__ == "__main__":
    unittest.main()
