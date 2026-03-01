"""Compatibility tests for legacy scan-history formats."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cyberpet.scan_history import ScanHistory


class ScanHistoryCompatibilityTests(unittest.TestCase):
    """Ensure older persisted status/timestamp formats still load."""

    def test_get_last_scan_accepts_legacy_completed_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "scan_history.db"
            history = ScanHistory(str(db_path))
            try:
                history._conn.execute(
                    """INSERT INTO scan_runs
                       (scan_type, started_at, completed_at, files_scanned, threats_found, status, duration_seconds)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        "quick",
                        "1700000000.0",
                        "1700000005.0",
                        99,
                        1,
                        "completed",
                        5.0,
                    ),
                )
                history._conn.commit()

                last = history.get_last_scan()
                self.assertIsNotNone(last)
                assert last is not None
                self.assertEqual(last["status"], "completed")
                self.assertEqual(last["files_scanned"], 99)
            finally:
                history.close()

    def test_claim_or_start_scan_reuses_recent_running_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "scan_history.db"
            history = ScanHistory(str(db_path))
            try:
                run_id = history.start_scan("quick")
                reused = history.claim_or_start_scan("quick", max_age_seconds=3600.0)
                self.assertEqual(reused, run_id)
            finally:
                history.close()

    def test_claim_or_start_scan_ignores_stale_running_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "scan_history.db"
            history = ScanHistory(str(db_path))
            try:
                history._conn.execute(
                    """INSERT INTO scan_runs
                       (scan_type, started_at, status)
                       VALUES (?, ?, ?)""",
                    ("quick", "1700000000.0", "running"),
                )
                history._conn.commit()
                new_id = history.claim_or_start_scan("quick", max_age_seconds=1.0)
                self.assertGreater(new_id, 1)
            finally:
                history.close()

    def test_cancel_all_running_marks_rows_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "scan_history.db"
            history = ScanHistory(str(db_path))
            try:
                history.start_scan("quick")
                history.start_scan("full")
                changed = history.cancel_all_running()
                self.assertGreaterEqual(changed, 2)
                rows = history._conn.execute(
                    "SELECT status, completed_at FROM scan_runs ORDER BY id DESC LIMIT 2"
                ).fetchall()
                self.assertTrue(all(r[0] == "cancelled" for r in rows))
                self.assertTrue(all(bool(r[1]) for r in rows))
            finally:
                history.close()

    def test_cancel_scan_persists_partial_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "scan_history.db"
            history = ScanHistory(str(db_path))
            try:
                run_id = history.start_scan("quick")
                history.cancel_scan(
                    run_id,
                    files_scanned=321,
                    threats_found=2,
                    duration_seconds=8.5,
                )
                row = history._conn.execute(
                    "SELECT status, files_scanned, threats_found, duration_seconds FROM scan_runs WHERE id = ?",
                    (run_id,),
                ).fetchone()
                self.assertIsNotNone(row)
                assert row is not None
                self.assertEqual(row[0], "cancelled")
                self.assertEqual(row[1], 321)
                self.assertEqual(row[2], 2)
                self.assertAlmostEqual(float(row[3] or 0.0), 8.5, places=2)
            finally:
                history.close()


if __name__ == "__main__":
    unittest.main()
