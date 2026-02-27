"""Tests for RLPriorKnowledge bootstrap module."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cyberpet.rl_prior import RLPriorKnowledge


class _FakeFPMemory:
    """Minimal FalsePositiveMemory stand-in for testing."""

    def __init__(self, fp_records=None, rl_export=None):
        self._fp_records = fp_records or []
        self._rl_export = rl_export or {}

    def export_for_rl(self) -> dict:
        return self._rl_export

    def get_all_false_positives(self) -> list[dict]:
        return self._fp_records


class _FakeScanHistory:
    """Minimal ScanHistory stand-in for testing."""

    def __init__(self, scans=None, threats_by_scan=None):
        self._scans = scans or []
        self._threats_by_scan = threats_by_scan or {}

    def get_scan_history(self, limit=100) -> list[dict]:
        return self._scans

    def get_threats_for_scan(self, scan_id: int) -> list[dict]:
        return self._threats_by_scan.get(scan_id, [])


class TestRLPriorKnowledgeEmpty(unittest.TestCase):
    """Test prior loading from empty databases."""

    def setUp(self) -> None:
        self.fp = _FakeFPMemory()
        self.history = _FakeScanHistory()
        self.prior = RLPriorKnowledge(self.fp, self.history)

    def test_load_empty_returns_valid_dict(self) -> None:
        data = self.prior.load()
        self.assertIsInstance(data, dict)
        self.assertEqual(data["total_fp_count"], 0)
        self.assertEqual(data["total_confirmed_threats"], 0)
        self.assertEqual(data["avg_threat_score_at_quarantine"], 0.0)
        self.assertIsInstance(data["safe_hashes"], set)
        self.assertIsInstance(data["threat_hashes"], set)

    def test_action_bias_neutral_when_empty(self) -> None:
        bias = self.prior.get_action_bias()
        self.assertEqual(len(bias), 8)
        for i in range(8):
            self.assertEqual(bias[i], 1.0)

    def test_safe_file_set_empty(self) -> None:
        safe = self.prior.get_safe_file_penalty_set()
        self.assertIsInstance(safe, set)
        self.assertEqual(len(safe), 0)

    def test_summarize_empty(self) -> None:
        summary = self.prior.summarize()
        self.assertIn("0 safe files", summary)
        self.assertIn("0 confirmed threats", summary)


class TestRLPriorKnowledgePopulated(unittest.TestCase):
    """Test prior loading with populated databases (8 safe + 3 threats)."""

    def setUp(self) -> None:
        fp_records = [
            {"sha256": f"safe_hash_{i}", "filepath": f"/path/safe_{i}"}
            for i in range(8)
        ]
        rl_export = {
            "safe_hashes": [f"safe_hash_{i}" for i in range(8)],
            "safe_paths": [f"/path/safe_{i}" for i in range(8)],
            "confirmed_threats": ["threat_hash_0", "threat_hash_1"],
            "fp_categories": {"cryptominer": 5, "webshell": 2, "trojan": 1},
            "fp_rules": {"CRYPTO_MINER": 5, "WEB_SHELL": 2, "GENERIC_TROJAN": 1},
        }
        scans = [{"id": 1}, {"id": 2}]
        threats_by_scan = {
            1: [
                {"action_taken": "quarantined", "threat_category": "cryptominer",
                 "threat_score": 85, "file_hash": "threat_hash_0"},
                {"action_taken": "marked_safe", "threat_category": "webshell",
                 "threat_score": 45, "file_hash": "safe_hash_0"},
            ],
            2: [
                {"action_taken": "quarantined", "threat_category": "cryptominer",
                 "threat_score": 90, "file_hash": "threat_hash_1"},
                {"action_taken": "quarantined", "threat_category": "trojan",
                 "threat_score": 92, "file_hash": "threat_hash_2"},
            ],
        }
        self.fp = _FakeFPMemory(fp_records=fp_records, rl_export=rl_export)
        self.history = _FakeScanHistory(scans=scans, threats_by_scan=threats_by_scan)
        self.prior = RLPriorKnowledge(self.fp, self.history)

    def test_load_counts(self) -> None:
        data = self.prior.load()
        self.assertEqual(data["total_fp_count"], 8)
        self.assertEqual(data["total_confirmed_threats"], 3)
        self.assertGreater(data["avg_threat_score_at_quarantine"], 0)

    def test_safe_hashes_populated(self) -> None:
        data = self.prior.load()
        self.assertEqual(len(data["safe_hashes"]), 8)
        self.assertIn("safe_hash_0", data["safe_hashes"])

    def test_threat_hashes_populated(self) -> None:
        data = self.prior.load()
        self.assertIn("threat_hash_0", data["threat_hashes"])
        self.assertIn("threat_hash_1", data["threat_hashes"])

    def test_confirmed_threat_categories(self) -> None:
        data = self.prior.load()
        cats = data["confirmed_threat_categories"]
        self.assertEqual(cats["cryptominer"], 2)
        self.assertEqual(cats["trojan"], 1)

    def test_action_bias_favors_quarantine(self) -> None:
        self.prior.load()
        bias = self.prior.get_action_bias()
        # 3 confirmed threats > 0 FPs in scan history → bias quarantine up
        self.assertGreater(bias[3], 1.0)  # QUARANTINE_FILE biased up

    def test_safe_file_penalty_set(self) -> None:
        self.prior.load()
        safe = self.prior.get_safe_file_penalty_set()
        self.assertEqual(len(safe), 8)

    def test_summarize_populated(self) -> None:
        self.prior.load()
        summary = self.prior.summarize()
        self.assertIn("8 safe files", summary)
        self.assertIn("3 confirmed threats", summary)

    def test_avg_threat_score(self) -> None:
        data = self.prior.load()
        # Scores: 85, 90, 92 → avg ≈ 89.0
        self.assertAlmostEqual(data["avg_threat_score_at_quarantine"], 89.0, places=0)


class TestRLPriorKnowledgeCorrupted(unittest.TestCase):
    """Test graceful handling of corrupted data."""

    def test_corrupted_fp_memory_returns_empty(self) -> None:
        fp = MagicMock()
        fp.export_for_rl.side_effect = Exception("DB corrupted")
        fp.get_all_false_positives.side_effect = Exception("DB corrupted")
        history = _FakeScanHistory()
        prior = RLPriorKnowledge(fp, history)
        data = prior.load()
        self.assertEqual(data["total_fp_count"], 0)

    def test_corrupted_scan_history_returns_partial(self) -> None:
        rl_export = {"safe_hashes": ["h1", "h2"], "safe_paths": ["/p1"]}
        fp = _FakeFPMemory(rl_export=rl_export)
        history = MagicMock()
        history.get_scan_history.side_effect = Exception("DB corrupted")
        prior = RLPriorKnowledge(fp, history)
        data = prior.load()
        self.assertEqual(data["total_fp_count"], 2)
        self.assertEqual(data["total_confirmed_threats"], 0)


if __name__ == "__main__":
    unittest.main()
