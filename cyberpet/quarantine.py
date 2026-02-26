"""Quarantine vault for CyberPet V2.

Isolates detected threats by copying them to a secure vault directory,
stripping permissions on the original, and killing processes holding
the file open.  Supports restore and permanent deletion.
"""

from __future__ import annotations

import os
import shutil
import signal
import sqlite3
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from cyberpet.events import Event, EventBus, EventType
from cyberpet.scanner import ThreatRecord


@dataclass
class QuarantineRecord:
    """A quarantined file entry."""

    quarantine_id: str
    original_path: str
    quarantine_time: str
    threat_score: int
    threat_reason: str
    file_hash: str
    malware_name: str
    status: str  # "quarantined", "restored", "deleted"
    original_mode: int = 0o644


class QuarantineVault:
    """Secure quarantine vault for isolated threat files.

    Usage:
        vault = QuarantineVault(event_bus=bus)
        qid = await vault.quarantine_file(filepath, threat_record)
        await vault.restore_file(qid)
    """

    def __init__(
        self,
        event_bus: EventBus,
        vault_path: str = "/var/lib/cyberpet/quarantine/",
    ) -> None:
        self.event_bus = event_bus
        self.vault_path = vault_path
        os.makedirs(vault_path, exist_ok=True)
        try:
            os.chmod(vault_path, 0o700)
        except OSError:
            pass

        db_path = os.path.join(vault_path, "quarantine.db")
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS quarantine (
                quarantine_id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                quarantine_time TEXT NOT NULL,
                threat_score INTEGER NOT NULL DEFAULT 0,
                threat_reason TEXT NOT NULL DEFAULT '',
                file_hash TEXT NOT NULL DEFAULT '',
                malware_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'quarantined',
                original_mode INTEGER NOT NULL DEFAULT 420
            );
        """)
        self._conn.commit()

    async def quarantine_file(
        self, filepath: str, threat_record: ThreatRecord
    ) -> str:
        """Quarantine a file: copy to vault, strip permissions, kill holders.

        This operation is atomic: if any step fails after the vault copy,
        we restore the original file's permissions and remove the vault copy.

        Args:
            filepath: Absolute path to the file to quarantine.
            threat_record: The scan result that triggered quarantine.

        Returns:
            The quarantine ID (UUID string).
        """
        # Resolve symlinks to get real path
        real_path = os.path.realpath(filepath)

        # Capture original permissions
        try:
            original_stat = os.stat(real_path)
            original_mode = stat.S_IMODE(original_stat.st_mode)
        except OSError as exc:
            raise RuntimeError(f"Cannot stat {real_path}: {exc}") from exc

        quarantine_id = uuid.uuid4().hex
        vault_file = os.path.join(self.vault_path, f"{quarantine_id}.quar")

        # Step 1: Copy file to vault
        try:
            shutil.copy2(real_path, vault_file)
        except OSError as exc:
            raise RuntimeError(f"Cannot copy to vault: {exc}") from exc

        # Step 2: Strip permissions on original (atomic point)
        try:
            os.chmod(real_path, 0o000)
        except OSError:
            # Rollback: remove vault copy
            try:
                os.unlink(vault_file)
            except OSError:
                pass
            raise

        # Step 3: Record in database
        now = datetime.now().isoformat()
        try:
            self._conn.execute(
                """INSERT INTO quarantine
                   (quarantine_id, original_path, quarantine_time,
                    threat_score, threat_reason, file_hash,
                    malware_name, status, original_mode)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'quarantined', ?)""",
                (
                    quarantine_id,
                    real_path,
                    now,
                    threat_record.threat_score,
                    threat_record.threat_reason,
                    threat_record.file_hash,
                    threat_record.threat_category,
                    original_mode,
                ),
            )
            self._conn.commit()
        except Exception:
            # Rollback: restore permissions and remove vault copy
            try:
                os.chmod(real_path, original_mode)
            except OSError:
                pass
            try:
                os.unlink(vault_file)
            except OSError:
                pass
            raise

        # Step 4: Kill processes holding the file open
        self._kill_file_holders(real_path)

        # Publish success event
        await self.event_bus.publish(Event(
            type=EventType.QUARANTINE_SUCCESS,
            source="quarantine",
            data={
                "quarantine_id": quarantine_id,
                "original_path": real_path,
                "threat_category": threat_record.threat_category,
            },
            severity=threat_record.threat_score,
        ))

        return quarantine_id

    async def list_quarantined(self) -> list[QuarantineRecord]:
        """List all quarantine records."""
        rows = self._conn.execute(
            """SELECT quarantine_id, original_path, quarantine_time,
                      threat_score, threat_reason, file_hash,
                      malware_name, status, original_mode
               FROM quarantine ORDER BY quarantine_time DESC"""
        ).fetchall()
        return [
            QuarantineRecord(
                quarantine_id=r[0],
                original_path=r[1],
                quarantine_time=r[2],
                threat_score=r[3],
                threat_reason=r[4],
                file_hash=r[5],
                malware_name=r[6],
                status=r[7],
                original_mode=r[8],
            )
            for r in rows
        ]

    async def restore_file(self, quarantine_id: str) -> bool:
        """Restore a quarantined file to its original location.

        Args:
            quarantine_id: Full or prefix of the quarantine UUID.

        Returns:
            True if restored successfully.
        """
        record = self._find_record(quarantine_id)
        if not record:
            return False

        vault_file = os.path.join(self.vault_path, f"{record.quarantine_id}.quar")
        if not os.path.exists(vault_file):
            return False

        # Copy back to original path — original has 0o000 perms, so remove first
        try:
            if os.path.exists(record.original_path):
                os.chmod(record.original_path, 0o600)
                os.unlink(record.original_path)
            shutil.copy2(vault_file, record.original_path)
            os.chmod(record.original_path, record.original_mode)
        except OSError:
            return False

        # Update database
        self._conn.execute(
            "UPDATE quarantine SET status = 'restored' WHERE quarantine_id = ?",
            (record.quarantine_id,),
        )
        self._conn.commit()

        # Remove vault copy
        try:
            os.unlink(vault_file)
        except OSError:
            pass

        return True

    async def delete_quarantined(self, quarantine_id: str) -> bool:
        """Permanently delete a quarantined file.

        Args:
            quarantine_id: Full or prefix of the quarantine UUID.

        Returns:
            True if deleted successfully.
        """
        record = self._find_record(quarantine_id)
        if not record:
            return False

        vault_file = os.path.join(self.vault_path, f"{record.quarantine_id}.quar")
        try:
            if os.path.exists(vault_file):
                os.unlink(vault_file)
        except OSError:
            pass

        self._conn.execute(
            "UPDATE quarantine SET status = 'deleted' WHERE quarantine_id = ?",
            (record.quarantine_id,),
        )
        self._conn.commit()
        return True

    def _find_record(self, quarantine_id: str) -> QuarantineRecord | None:
        """Find a quarantine record by full ID or prefix."""
        row = self._conn.execute(
            """SELECT quarantine_id, original_path, quarantine_time,
                      threat_score, threat_reason, file_hash,
                      malware_name, status, original_mode
               FROM quarantine WHERE quarantine_id = ? AND status = 'quarantined'""",
            (quarantine_id,),
        ).fetchone()

        if not row:
            # Try prefix match
            rows = self._conn.execute(
                """SELECT quarantine_id, original_path, quarantine_time,
                          threat_score, threat_reason, file_hash,
                          malware_name, status, original_mode
                   FROM quarantine
                   WHERE quarantine_id LIKE ? AND status = 'quarantined'
                   LIMIT 2""",
                (quarantine_id + "%",),
            ).fetchall()

            # Refuse ambiguous prefixes to avoid restoring/deleting wrong files.
            if len(rows) != 1:
                return None
            row = rows[0]

        if not row:
            return None

        return QuarantineRecord(
            quarantine_id=row[0],
            original_path=row[1],
            quarantine_time=row[2],
            threat_score=row[3],
            threat_reason=row[4],
            file_hash=row[5],
            malware_name=row[6],
            status=row[7],
            original_mode=row[8],
        )

    @staticmethod
    def _kill_file_holders(filepath: str) -> None:
        """Send SIGTERM to processes that have filepath open."""
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                fd_dir = f"/proc/{pid_dir}/fd"
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(os.path.join(fd_dir, fd))
                            if link == filepath:
                                os.kill(int(pid_dir), signal.SIGTERM)
                                break
                        except (OSError, ValueError):
                            pass
                except OSError:
                    pass
        except OSError:
            pass

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
