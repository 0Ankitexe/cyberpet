"""False positive memory for CyberPet V2.

Records user decisions (mark-safe / quarantine-confirm) in SQLite
so that:
  1. Files marked safe never reappear in future scans.
  2. Decision data can be exported for future RL training.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any


class FalsePositiveMemory:
    """SQLite-backed false-positive / quarantine-confirmation store.

    Usage::

        fpm = FalsePositiveMemory()
        fpm.record_false_positive(threat_record)
        if fpm.is_known_false_positive(sha256, filepath):
            ...  # skip this file
    """

    def __init__(
        self, db_path: str = "/var/lib/cyberpet/false_positives.db",
    ) -> None:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                threat_category TEXT,
                threat_score INTEGER,
                matched_rules TEXT,
                marked_safe_at TEXT,
                mark_count INTEGER DEFAULT 1,
                UNIQUE(sha256)
            );

            CREATE TABLE IF NOT EXISTS quarantine_confirmations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                threat_category TEXT,
                threat_score INTEGER,
                matched_rules TEXT,
                quarantined_at TEXT,
                user_confirmed INTEGER DEFAULT 1
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_false_positive(self, threat: Any) -> None:
        """Mark a threat as a false positive.

        If the same sha256 was already marked safe, increments
        ``mark_count`` instead of inserting a duplicate.
        """
        rules = json.dumps(threat.matched_rules) if threat.matched_rules else "[]"
        now = datetime.now().isoformat()

        existing = self._conn.execute(
            "SELECT id, mark_count FROM false_positives WHERE sha256 = ?",
            (threat.file_hash,),
        ).fetchone()

        if existing:
            self._conn.execute(
                "UPDATE false_positives SET mark_count = ?, marked_safe_at = ?, filepath = ? WHERE id = ?",
                (existing[1] + 1, now, threat.filepath, existing[0]),
            )
        else:
            self._conn.execute(
                """INSERT INTO false_positives
                   (filepath, sha256, threat_category, threat_score, matched_rules, marked_safe_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (threat.filepath, threat.file_hash, threat.threat_category,
                 threat.threat_score, rules, now),
            )
        self._conn.commit()
        self._export_for_rl()

    def record_quarantine_confirmation(self, threat: Any) -> None:
        """Record that the user explicitly confirmed quarantine."""
        rules = json.dumps(threat.matched_rules) if threat.matched_rules else "[]"
        now = datetime.now().isoformat()
        self._conn.execute(
            """INSERT INTO quarantine_confirmations
               (filepath, sha256, threat_category, threat_score, matched_rules, quarantined_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (threat.filepath, threat.file_hash, threat.threat_category,
             threat.threat_score, rules, now),
        )
        self._conn.commit()
        self._export_for_rl()

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def is_known_false_positive(self, sha256: str, filepath: str = "") -> bool:
        """Return True if this file was ever marked safe (by hash or path)."""
        row = self._conn.execute(
            "SELECT 1 FROM false_positives WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if row:
            return True
        if filepath:
            row = self._conn.execute(
                "SELECT 1 FROM false_positives WHERE filepath = ?",
                (filepath,),
            ).fetchone()
            return row is not None
        return False

    def get_all_false_positives(self) -> list[dict[str, Any]]:
        """Return all false positive entries as a list of dicts."""
        rows = self._conn.execute(
            """SELECT sha256, filepath, threat_category, threat_score,
                      matched_rules, marked_safe_at, mark_count
               FROM false_positives ORDER BY id DESC""",
        ).fetchall()
        return [
            {
                "sha256": r[0],
                "filepath": r[1],
                "threat_category": r[2],
                "threat_score": r[3],
                "matched_rules": r[4],
                "added_at": r[5],
                "mark_count": r[6],
            }
            for r in rows
        ]

    def clear_all(self) -> int:
        """Delete all FP and quarantine confirmation entries. Returns count deleted."""
        cur = self._conn.execute("SELECT COUNT(*) FROM false_positives")
        count = cur.fetchone()[0]
        self._conn.execute("DELETE FROM false_positives")
        self._conn.execute("DELETE FROM quarantine_confirmations")
        self._conn.commit()
        return count

    def get_false_positive_patterns(self) -> dict[str, Any]:
        """Return aggregated FP patterns for analysis / RL."""
        rows = self._conn.execute(
            "SELECT threat_category, matched_rules, filepath, sha256 FROM false_positives",
        ).fetchall()

        by_category: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        trusted_paths: list[str] = []
        trusted_hashes: list[str] = []

        for cat, rules_json, fp, sha in rows:
            by_category[cat] = by_category.get(cat, 0) + 1
            trusted_paths.append(fp)
            trusted_hashes.append(sha)
            try:
                for rule in json.loads(rules_json):
                    by_rule[rule] = by_rule.get(rule, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "total_fps": len(rows),
            "by_category": by_category,
            "by_rule": by_rule,
            "trusted_paths": trusted_paths,
            "trusted_hashes": trusted_hashes,
        }

    # ------------------------------------------------------------------
    # RL export
    # ------------------------------------------------------------------

    def export_for_rl(self) -> dict[str, Any]:
        """Export all decision data for RL prior loading.

        Returns a dict with safe_hashes, safe_paths, confirmed_threats,
        fp_categories, and fp_rules.
        """
        return self._export_for_rl()

    def _export_for_rl(self) -> dict[str, Any]:
        """Export all decision data to JSON for future RL training."""
        fp_rows = self._conn.execute(
            "SELECT sha256, filepath, threat_category, matched_rules FROM false_positives",
        ).fetchall()
        qc_rows = self._conn.execute(
            "SELECT sha256, filepath, threat_category, matched_rules FROM quarantine_confirmations",
        ).fetchall()

        fp_categories: dict[str, int] = {}
        fp_rules: dict[str, int] = {}
        for _, _, cat, rules_json in fp_rows:
            fp_categories[cat] = fp_categories.get(cat, 0) + 1
            try:
                for r in json.loads(rules_json):
                    fp_rules[r] = fp_rules.get(r, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        data = {
            "safe_hashes": [r[0] for r in fp_rows],
            "safe_paths": [r[1] for r in fp_rows],
            "confirmed_threats": [r[0] for r in qc_rows],
            "fp_categories": fp_categories,
            "fp_rules": fp_rules,
        }

        rl_path = "/var/lib/cyberpet/rl_feedback.json"
        try:
            with open(rl_path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError:
            pass  # non-critical — tolerate permission issues

        return data

    def close(self) -> None:
        self._conn.close()
