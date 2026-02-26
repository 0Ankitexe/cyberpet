"""Tests for cyberpet.quarantine — quarantine vault system."""

import asyncio
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from cyberpet.events import EventBus
from cyberpet.quarantine import QuarantineVault
from cyberpet.scanner import ThreatRecord


class QuarantineTests(unittest.TestCase):
    """Unit tests for QuarantineVault."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._vault_dir = os.path.join(self._tmpdir, "vault")
        self._bus = EventBus()
        self._vault = QuarantineVault(self._bus, self._vault_dir)
        self._loop = asyncio.new_event_loop()

    def tearDown(self):
        self._vault.close()
        self._loop.close()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_threat_file(self, content: str = "malicious content") -> tuple[str, ThreatRecord]:
        """Create a temp file and a matching ThreatRecord."""
        fp = os.path.join(self._tmpdir, "threat_test.bin")
        with open(fp, "w") as f:
            f.write(content)
        os.chmod(fp, 0o644)
        record = ThreatRecord(
            filepath=fp,
            threat_score=90,
            threat_reason="Test threat",
            file_hash="abcd1234" * 8,
            threat_category="unknown_malware",
            recommended_action="quarantine",
        )
        return fp, record

    def test_quarantine_copies_to_vault_and_strips_perms(self):
        """Quarantining should copy to vault and set original perms to 000."""
        fp, record = self._make_threat_file()

        qid = self._loop.run_until_complete(
            self._vault.quarantine_file(fp, record)
        )

        # Vault file should exist
        vault_file = os.path.join(self._vault_dir, f"{qid}.quar")
        self.assertTrue(os.path.exists(vault_file))

        # Original should have 000 permissions
        mode = stat.S_IMODE(os.stat(fp).st_mode)
        self.assertEqual(mode, 0o000)

    def test_restore_restores_original_path_and_perms(self):
        """Restoring should copy back and restore original permissions."""
        fp, record = self._make_threat_file()

        qid = self._loop.run_until_complete(
            self._vault.quarantine_file(fp, record)
        )

        restored = self._loop.run_until_complete(
            self._vault.restore_file(qid)
        )

        self.assertTrue(restored)
        self.assertTrue(os.path.exists(fp))
        mode = stat.S_IMODE(os.stat(fp).st_mode)
        self.assertEqual(mode, 0o644)

        # Vault file should be removed
        vault_file = os.path.join(self._vault_dir, f"{qid}.quar")
        self.assertFalse(os.path.exists(vault_file))

    def test_delete_removes_vault_file(self):
        """Deleting should remove the vault copy permanently."""
        fp, record = self._make_threat_file()

        qid = self._loop.run_until_complete(
            self._vault.quarantine_file(fp, record)
        )

        deleted = self._loop.run_until_complete(
            self._vault.delete_quarantined(qid)
        )

        self.assertTrue(deleted)
        vault_file = os.path.join(self._vault_dir, f"{qid}.quar")
        self.assertFalse(os.path.exists(vault_file))

    def test_list_shows_quarantined_files(self):
        """list_quarantined should include all quarantined records."""
        fp, record = self._make_threat_file()

        self._loop.run_until_complete(
            self._vault.quarantine_file(fp, record)
        )

        records = self._loop.run_until_complete(
            self._vault.list_quarantined()
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, "quarantined")
        self.assertEqual(records[0].original_path, os.path.realpath(fp))

    def test_invalid_quarantine_id_returns_false(self):
        """Restoring with an invalid ID should return False."""
        restored = self._loop.run_until_complete(
            self._vault.restore_file("nonexistent_id")
        )
        self.assertFalse(restored)

    def test_prefix_match_restore(self):
        """Restore should work with a prefix of the quarantine ID."""
        fp, record = self._make_threat_file()

        qid = self._loop.run_until_complete(
            self._vault.quarantine_file(fp, record)
        )

        # Use first 8 chars as prefix
        prefix = qid[:8]
        restored = self._loop.run_until_complete(
            self._vault.restore_file(prefix)
        )
        self.assertTrue(restored)

    def test_ambiguous_prefix_restore_is_rejected(self):
        """Restore should refuse ambiguous ID prefixes."""
        fp1, record1 = self._make_threat_file("malicious content 1")
        fp2 = os.path.join(self._tmpdir, "threat_test_2.bin")
        with open(fp2, "w") as f:
            f.write("malicious content 2")
        os.chmod(fp2, 0o644)
        record2 = ThreatRecord(
            filepath=fp2,
            threat_score=90,
            threat_reason="Test threat 2",
            file_hash="dcba4321" * 8,
            threat_category="unknown_malware",
            recommended_action="quarantine",
        )

        class _UuidStub:
            def __init__(self, hex_value: str) -> None:
                self.hex = hex_value

        with patch(
            "cyberpet.quarantine.uuid.uuid4",
            side_effect=[
                _UuidStub("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                _UuidStub("aaaabbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ],
        ):
            self._loop.run_until_complete(self._vault.quarantine_file(fp1, record1))
            self._loop.run_until_complete(self._vault.quarantine_file(fp2, record2))

        restored = self._loop.run_until_complete(self._vault.restore_file("aaaa"))
        self.assertFalse(restored)


if __name__ == "__main__":
    unittest.main()
