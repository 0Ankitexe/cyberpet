"""Tests for cyberpet.yara_engine — YARA rule compilation and scanning."""

import os
import tempfile
import unittest

from cyberpet.yara_engine import YaraEngine, YaraMatch


class YaraEngineTests(unittest.TestCase):
    """Unit tests for YaraEngine."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        # Create a minimal test rule
        self._rule_file = os.path.join(self._tmpdir, "test.yar")
        with open(self._rule_file, "w") as f:
            f.write(
                'rule TestMiner {\n'
                '    meta:\n'
                '        category = "cryptominer"\n'
                '        severity = "high"\n'
                '    strings:\n'
                '        $s1 = "stratum+tcp://"\n'
                '    condition:\n'
                '        $s1\n'
                '}\n'
            )

    def tearDown(self):
        import shutil
        if os.path.exists(self._rule_file):
            os.unlink(self._rule_file)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_load_and_compile_rules(self):
        """Rules should compile from a directory of .yar files."""
        engine = YaraEngine(self._tmpdir)
        if not engine.available:
            self.skipTest("yara-python not installed")
        self.assertTrue(engine.compile_rules())

    def test_scan_bytes_matching(self):
        """Scanning bytes with known rule content should produce matches."""
        engine = YaraEngine(self._tmpdir)
        if not engine.available:
            self.skipTest("yara-python not installed")
        matches = engine.scan_bytes(b'connecting to stratum+tcp://pool.example.com')
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].rule_name, "TestMiner")
        self.assertEqual(matches[0].category, "cryptominer")

    def test_scan_bytes_no_match(self):
        """Scanning innocent bytes should produce no matches."""
        engine = YaraEngine(self._tmpdir)
        if not engine.available:
            self.skipTest("yara-python not installed")
        matches = engine.scan_bytes(b'hello world this is perfectly normal')
        self.assertEqual(len(matches), 0)

    def test_invalid_rule_file_is_skipped(self):
        """A bad rule file should be skipped; good rules still load."""
        bad_file = os.path.join(self._tmpdir, "bad.yar")
        with open(bad_file, "w") as f:
            f.write("rule Bad { condition: INVALID_SYNTAX")
        engine = YaraEngine(self._tmpdir)
        if not engine.available:
            self.skipTest("yara-python not installed")
        result = engine.compile_rules()
        self.assertTrue(result)  # Good rule should still load
        # Verify scanning still works
        matches = engine.scan_bytes(b'stratum+tcp://pool')
        self.assertGreater(len(matches), 0)
        os.unlink(bad_file)

    def test_empty_directory(self):
        """Compiling with an empty directory should return False."""
        empty_dir = tempfile.mkdtemp()
        engine = YaraEngine(empty_dir)
        if not engine.available:
            self.skipTest("yara-python not installed")
        self.assertFalse(engine.compile_rules())
        os.rmdir(empty_dir)

    def test_categorize_matches(self):
        """categorize_matches should return highest priority category."""
        matches = [
            YaraMatch(rule_name="R1", category="cryptominer"),
            YaraMatch(rule_name="R2", category="ransomware"),
        ]
        self.assertEqual(YaraEngine.categorize_matches(matches), "ransomware")

    def test_categorize_empty_matches(self):
        """categorize_matches with no input should return unknown_malware."""
        self.assertEqual(YaraEngine.categorize_matches([]), "unknown_malware")


if __name__ == "__main__":
    unittest.main()
