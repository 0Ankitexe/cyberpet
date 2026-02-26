"""Local SHA256 hash database for CyberPet V2.

Provides fast lookup of known-malware and known-clean file hashes
backed by SQLite with WAL mode for concurrent read access during scans.
"""

from __future__ import annotations

import csv
import os
import sqlite3
from typing import Optional


class HashDatabase:
    """SQLite-backed hash database for malware and clean file identification.

    Schema:
        malware_hashes — SHA256 keyed with malware name and threat level
        clean_hashes   — SHA256 keyed with original filepath

    Usage:
        db = HashDatabase("/var/lib/cyberpet/hashes.db")
        is_bad, name, level = db.is_malware(sha256)
    """

    def __init__(self, db_path: str = "/var/lib/cyberpet/hashes.db") -> None:
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()

    def _create_tables(self) -> None:
        """Create tables if they don't exist."""
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS malware_hashes (
                sha256 TEXT PRIMARY KEY,
                malware_name TEXT NOT NULL,
                threat_level INTEGER NOT NULL DEFAULT 80,
                added_date TEXT NOT NULL DEFAULT (date('now'))
            );
            CREATE TABLE IF NOT EXISTS clean_hashes (
                sha256 TEXT PRIMARY KEY,
                filepath TEXT NOT NULL,
                added_date TEXT NOT NULL DEFAULT (date('now'))
            );
        """)
        self._conn.commit()

    def is_malware(self, sha256: str) -> tuple[bool, str, int]:
        """Check if a SHA256 hash is known malware.

        Args:
            sha256: Hex-encoded SHA256 digest.

        Returns:
            (is_malware, malware_name, threat_level)
            Returns (False, "", 0) if not found.
        """
        row = self._conn.execute(
            "SELECT malware_name, threat_level FROM malware_hashes WHERE sha256 = ?",
            (sha256.lower(),),
        ).fetchone()
        if row:
            return True, row[0], row[1]
        return False, "", 0

    def add_malware(self, sha256: str, name: str, level: int) -> None:
        """Add or update a known malware hash.

        Args:
            sha256: Hex-encoded SHA256 digest.
            name: Malware name or family.
            level: Threat severity 0–100.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO malware_hashes (sha256, malware_name, threat_level) VALUES (?, ?, ?)",
            (sha256.lower(), name, max(0, min(100, level))),
        )
        self._conn.commit()

    def is_known_clean(self, sha256: str) -> bool:
        """Check if a SHA256 hash is known clean.

        Args:
            sha256: Hex-encoded SHA256 digest.

        Returns:
            True if the hash is in the clean database.
        """
        row = self._conn.execute(
            "SELECT 1 FROM clean_hashes WHERE sha256 = ?",
            (sha256.lower(),),
        ).fetchone()
        return row is not None

    def add_clean(self, sha256: str, filepath: str) -> None:
        """Add a known-clean file hash.

        Args:
            sha256: Hex-encoded SHA256 digest.
            filepath: Original file path.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO clean_hashes (sha256, filepath) VALUES (?, ?)",
            (sha256.lower(), filepath),
        )
        self._conn.commit()

    def bulk_import_from_csv(self, filepath: str) -> int:
        """Import malware hashes from a CSV file.

        CSV columns: sha256, malware_name, threat_level

        Args:
            filepath: Path to the CSV file.

        Returns:
            Number of hashes imported.
        """
        if not os.path.exists(filepath):
            return 0
        count = 0
        with open(filepath, "r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 3:
                    continue
                sha256, name, level_str = row[0].strip(), row[1].strip(), row[2].strip()
                if not sha256 or sha256.startswith("#"):
                    continue
                try:
                    level = int(level_str)
                except ValueError:
                    level = 80
                self._conn.execute(
                    "INSERT OR REPLACE INTO malware_hashes (sha256, malware_name, threat_level) VALUES (?, ?, ?)",
                    (sha256.lower(), name, max(0, min(100, level))),
                )
                count += 1
        self._conn.commit()
        return count

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
