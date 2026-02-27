"""Tests for SystemStateCollector."""

from __future__ import annotations

import time
import unittest
from collections import deque
from unittest.mock import MagicMock, patch

import numpy as np

from cyberpet.events import Event, EventBus, EventType
from cyberpet.state import PetState
from cyberpet.state_collector import STATE_DIM, SystemStateCollector


class _MockPetState:
    """Lightweight PetState stand-in."""
    files_quarantined = 2
    last_scan_threats_found = 1
    last_scan_type = ""
    last_scan_time = 0.0


class TestStateVectorShape(unittest.TestCase):
    """Verify vector dimensions and normalisation."""

    def setUp(self) -> None:
        self.bus = EventBus()
        self.pet = _MockPetState()
        self.sc = SystemStateCollector(self.bus, self.pet)

    def test_shape_is_44(self) -> None:
        vec = self.sc.collect()
        self.assertEqual(vec.shape, (STATE_DIM,))
        self.assertEqual(STATE_DIM, 44)

    def test_dtype_float32(self) -> None:
        vec = self.sc.collect()
        self.assertEqual(vec.dtype, np.float32)

    def test_values_in_range(self) -> None:
        vec = self.sc.collect()
        for i, v in enumerate(vec):
            self.assertGreaterEqual(float(v), 0.0, f"Feature {i} below 0: {v}")
            self.assertLessEqual(float(v), 1.0, f"Feature {i} above 1: {v}")


class TestEventDrivenUpdates(unittest.TestCase):
    """Verify counters update from events."""

    def setUp(self) -> None:
        self.bus = EventBus()
        self.pet = _MockPetState()
        self.sc = SystemStateCollector(self.bus, self.pet)

    def test_cmd_blocked_counter(self) -> None:
        now = time.time()
        for _ in range(5):
            self.sc._handle_event(
                Event(type=EventType.CMD_BLOCKED, source="test"), now
            )
        self.assertEqual(self.sc._count_recent(self.sc._cmd_blocked_hour, now), 5)

    def test_quarantine_pushes_to_threat_history(self) -> None:
        now = time.time()
        self.sc._handle_event(
            Event(type=EventType.QUARANTINE_SUCCESS, source="test",
                  data={"threat_score": 85}),
            now,
        )
        self.assertEqual(self.sc._threat_scores[-1], 85.0)


class TestScanQualityMetrics(unittest.TestCase):
    """Verify scan quality feature calculations."""

    def setUp(self) -> None:
        self.bus = EventBus()
        self.pet = _MockPetState()
        self.sc = SystemStateCollector(self.bus, self.pet)

    def test_pkg_verified_ratio(self) -> None:
        now = time.time()
        self.sc._handle_event(
            Event(type=EventType.SCAN_COMPLETE, source="test",
                  data={"files_scanned": 1000, "skipped_pkg_verified": 500,
                        "threats_found": 3}),
            now,
        )
        self.assertAlmostEqual(self.sc._pkg_verified_ratio, 0.5, places=2)

    def test_fp_rate_recent(self) -> None:
        now = time.time()
        # Simulate 10 threats flagged
        self.sc._handle_event(
            Event(type=EventType.SCAN_COMPLETE, source="test",
                  data={"files_scanned": 100, "skipped_pkg_verified": 10,
                        "threats_found": 10}),
            now,
        )
        # 3 marked safe
        for _ in range(3):
            self.sc._handle_event(
                Event(type=EventType.FP_MARKED_SAFE, source="test",
                      data={"filepath": "/tmp/safe", "sha256": "abc"}),
                now,
            )
        rate = self.sc._fp_rate_recent()
        self.assertAlmostEqual(rate, 0.3, places=2)

    def test_fp_rate_zero_when_no_threats(self) -> None:
        rate = self.sc._fp_rate_recent()
        self.assertEqual(rate, 0.0)


class TestSyscallAnomaly(unittest.TestCase):
    """Verify anomaly score updates."""

    def setUp(self) -> None:
        self.bus = EventBus()
        self.pet = _MockPetState()
        self.sc = SystemStateCollector(self.bus, self.pet)

    def test_anomaly_score_increases(self) -> None:
        now = time.time()
        self.sc._handle_event(
            Event(type=EventType.SYSCALL_ANOMALY, source="test",
                  data={"severity": 80}),
            now,
        )
        self.assertGreater(self.sc._anomaly_score, 0.0)
        self.assertLessEqual(self.sc._anomaly_score, 1.0)

    def test_update_anomaly_directly(self) -> None:
        self.sc.update_anomaly_score(0.7)
        self.assertAlmostEqual(self.sc._anomaly_score, 0.7)

    def test_anomaly_clamped(self) -> None:
        self.sc.update_anomaly_score(1.5)
        self.assertLessEqual(self.sc._anomaly_score, 1.0)


class TestStateCollectorUS3ScanQuality(unittest.TestCase):
    """T024: Verify scan quality metric calculations as specified."""

    def setUp(self) -> None:
        self.bus = EventBus()
        self.pet = _MockPetState()
        self.sc = SystemStateCollector(self.bus, self.pet)

    def test_pkg_verified_ratio_half(self) -> None:
        """SCAN_COMPLETE with 500/1000 verified → ratio = 0.5."""
        now = time.time()
        self.sc._handle_event(
            Event(type=EventType.SCAN_COMPLETE, source="test",
                  data={"files_scanned": 1000, "skipped_pkg_verified": 500,
                        "threats_found": 2}),
            now,
        )
        self.assertAlmostEqual(self.sc._pkg_verified_ratio, 0.5, places=2)

    def test_fp_rate_3_of_10(self) -> None:
        """3 marks safe out of 10 threats → rate = 0.3."""
        now = time.time()
        self.sc._handle_event(
            Event(type=EventType.SCAN_COMPLETE, source="test",
                  data={"files_scanned": 100, "skipped_pkg_verified": 10,
                        "threats_found": 10}),
            now,
        )
        for _ in range(3):
            self.sc._handle_event(
                Event(type=EventType.FP_MARKED_SAFE, source="test",
                      data={"filepath": "/tmp/fp", "sha256": "x"}),
                now,
            )
        rate = self.sc._fp_rate_recent()
        self.assertAlmostEqual(rate, 0.3, places=2)

    def test_threat_history_sliding_window(self) -> None:
        """Threat scores push to sliding window correctly."""
        now = time.time()
        for score in [10, 20, 30, 40, 50, 60, 70, 80, 90]:
            self.sc._handle_event(
                Event(type=EventType.QUARANTINE_SUCCESS, source="test",
                      data={"threat_score": score}),
                now,
            )
        # Window is size 8, so oldest (10) should be pushed out
        self.assertEqual(len(self.sc._threat_scores), 8)
        self.assertAlmostEqual(self.sc._threat_scores[-1], 90.0)
        self.assertAlmostEqual(self.sc._threat_scores[0], 20.0)

    def test_multiple_scans_update_ratio(self) -> None:
        """Multiple SCAN_COMPLETE events update ratio to latest."""
        now = time.time()
        self.sc._handle_event(
            Event(type=EventType.SCAN_COMPLETE, source="test",
                  data={"files_scanned": 100, "skipped_pkg_verified": 50,
                        "threats_found": 1}),
            now,
        )
        self.assertAlmostEqual(self.sc._pkg_verified_ratio, 0.5)
        self.sc._handle_event(
            Event(type=EventType.SCAN_COMPLETE, source="test",
                  data={"files_scanned": 200, "skipped_pkg_verified": 150,
                        "threats_found": 0}),
            now,
        )
        self.assertAlmostEqual(self.sc._pkg_verified_ratio, 0.75)


if __name__ == "__main__":
    unittest.main()
