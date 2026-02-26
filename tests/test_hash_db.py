"""Tests for cyberpet.hash_db — SHA256 hash database."""

import os
import tempfile
import unittest

from cyberpet.hash_db import HashDatabase


EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class HashDatabaseTests(unittest.TestCase):
    """Unit tests for HashDatabase."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self._tmpdir, "test_hashes.db")
        self.db = HashDatabase(self.db_path)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        os.rmdir(self._tmpdir)

    def test_add_and_lookup_malware_hash(self):
        """Inserting a malware hash should be retrievable."""
        self.db.add_malware("aabbccdd" * 8, "TestMalware", 90)
        is_mal, name, level = self.db.is_malware("aabbccdd" * 8)
        self.assertTrue(is_mal)
        self.assertEqual(name, "TestMalware")
        self.assertEqual(level, 90)

    def test_unknown_hash_returns_false(self):
        """A hash not in the database should return False."""
        is_mal, name, level = self.db.is_malware("deadbeef" * 8)
        self.assertFalse(is_mal)
        self.assertEqual(name, "")
        self.assertEqual(level, 0)

    def test_add_and_lookup_clean_hash(self):
        """Inserting a clean hash should be queryable."""
        self.db.add_clean("cafebabe" * 8, "/usr/bin/ls")
        self.assertTrue(self.db.is_known_clean("cafebabe" * 8))

    def test_unknown_clean_hash_returns_false(self):
        """A hash not marked clean should return False."""
        self.assertFalse(self.db.is_known_clean("00112233" * 8))

    def test_eicar_hash_from_csv_import(self):
        """The EICAR test hash should be importable from the seed CSV."""
        seed = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "seed_hashes.csv")
        if not os.path.exists(seed):
            self.skipTest("seed_hashes.csv not found")
        count = self.db.bulk_import_from_csv(seed)
        self.assertGreater(count, 0)
        is_mal, name, level = self.db.is_malware(EICAR_SHA256)
        self.assertTrue(is_mal)
        self.assertEqual(name, "EICAR-Test-File")
        self.assertGreaterEqual(level, 80)

    def test_bulk_import_missing_file(self):
        """Importing from a nonexistent file should return 0."""
        count = self.db.bulk_import_from_csv("/nonexistent/path.csv")
        self.assertEqual(count, 0)

    def test_threat_level_clamped(self):
        """Threat level should be clamped to 0-100."""
        self.db.add_malware("11223344" * 8, "OverLevel", 200)
        is_mal, name, level = self.db.is_malware("11223344" * 8)
        self.assertTrue(is_mal)
        self.assertEqual(level, 100)


if __name__ == "__main__":
    unittest.main()
