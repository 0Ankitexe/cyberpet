"""Scan history persistence for CyberPet V2.

Stores completed scan runs and their associated threats in SQLite
so the TUI can display previous scan results and track per-threat
user actions (quarantined / marked safe / ignored).
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any


class ScanHistory:
    """SQLite-backed scan history store.

    Usage::

        history = ScanHistory()
        run_id = history.start_scan("quick")
        history.add_threat(run_id, threat_record)
        history.complete_scan(run_id, files_scanned=412, threats_found=2)
    """

    def __init__(
        self, db_path: str = "/var/lib/cyberpet/scan_history.db",
    ) -> None:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()

    # ------------------------------------------------------------------

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                files_scanned INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                threats_quarantined INTEGER DEFAULT 0,
                threats_marked_safe INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running',
                duration_seconds REAL
            );

            CREATE TABLE IF NOT EXISTS scan_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER REFERENCES scan_runs(id),
                filepath TEXT NOT NULL,
                sha256 TEXT,
                threat_score INTEGER,
                threat_category TEXT,
                threat_reason TEXT,
                matched_rules TEXT,
                action_taken TEXT DEFAULT 'pending',
                action_at TEXT
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def start_scan(self, scan_type: str) -> int:
        """Record a new scan run.  Returns the ``scan_run_id``."""
        now = datetime.now().isoformat()
        cur = self._conn.execute(
            "INSERT INTO scan_runs (scan_type, started_at) VALUES (?, ?)",
            (scan_type, now),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def add_threat(self, scan_run_id: int, threat: Any) -> int:
        """Persist a detected threat.  Returns the row id."""
        rules = json.dumps(threat.matched_rules) if threat.matched_rules else "[]"
        cur = self._conn.execute(
            """INSERT INTO scan_threats
               (scan_run_id, filepath, sha256, threat_score, threat_category,
                threat_reason, matched_rules)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_run_id,
                threat.filepath,
                threat.file_hash,
                threat.threat_score,
                threat.threat_category,
                threat.threat_reason,
                rules,
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def update_threat_action(
        self, scan_run_id: int, filepath: str, action: str,
    ) -> None:
        """Mark a threat as quarantined / marked_safe / ignored."""
        now = datetime.now().isoformat()
        self._conn.execute(
            """UPDATE scan_threats
               SET action_taken = ?, action_at = ?
               WHERE scan_run_id = ? AND filepath = ?""",
            (action, now, scan_run_id, filepath),
        )
        # Update summary counters
        if action == "quarantined":
            self._conn.execute(
                "UPDATE scan_runs SET threats_quarantined = threats_quarantined + 1 WHERE id = ?",
                (scan_run_id,),
            )
        elif action == "marked_safe":
            self._conn.execute(
                "UPDATE scan_runs SET threats_marked_safe = threats_marked_safe + 1 WHERE id = ?",
                (scan_run_id,),
            )
        self._conn.commit()

    def complete_scan(
        self,
        scan_run_id: int,
        files_scanned: int = 0,
        threats_found: int = 0,
        duration_seconds: float = 0.0,
    ) -> None:
        """Mark a scan as complete."""
        now = datetime.now().isoformat()
        self._conn.execute(
            """UPDATE scan_runs
               SET status = 'complete', completed_at = ?,
                   files_scanned = ?, threats_found = ?,
                   duration_seconds = ?
               WHERE id = ?""",
            (now, files_scanned, threats_found, duration_seconds, scan_run_id),
        )
        self._conn.commit()

    def cancel_scan(self, scan_run_id: int) -> None:
        """Mark a scan as cancelled."""
        now = datetime.now().isoformat()
        self._conn.execute(
            """UPDATE scan_runs
               SET status = 'cancelled', completed_at = ?
               WHERE id = ?""",
            (now, scan_run_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_last_scan(self, scan_type: str | None = None) -> dict[str, Any] | None:
        """Return the most recent completed/cancelled scan summary."""
        if scan_type:
            row = self._conn.execute(
                """SELECT id, scan_type, started_at, completed_at,
                          files_scanned, threats_found, status, duration_seconds
                   FROM scan_runs
                   WHERE scan_type = ? AND status IN ('complete', 'cancelled')
                   ORDER BY id DESC LIMIT 1""",
                (scan_type,),
            ).fetchone()
        else:
            row = self._conn.execute(
                """SELECT id, scan_type, started_at, completed_at,
                          files_scanned, threats_found, status, duration_seconds
                   FROM scan_runs
                   WHERE status IN ('complete', 'cancelled')
                   ORDER BY id DESC LIMIT 1""",
            ).fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "scan_type": row[1],
            "started_at": row[2],
            "completed_at": row[3],
            "files_scanned": row[4],
            "threats_found": row[5],
            "status": row[6],
            "duration_seconds": row[7],
        }

    def get_scan_history(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent scan summaries (newest first)."""
        rows = self._conn.execute(
            """SELECT id, scan_type, started_at, completed_at,
                      files_scanned, threats_found, status, duration_seconds
               FROM scan_runs ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "id": r[0], "scan_type": r[1], "started_at": r[2],
                "completed_at": r[3], "files_scanned": r[4],
                "threats_found": r[5], "status": r[6],
                "duration_seconds": r[7],
            }
            for r in rows
        ]

    def close(self) -> None:
        self._conn.close()
