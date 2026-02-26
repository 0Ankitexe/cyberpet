"""Config loader regression tests."""

from __future__ import annotations

import os
import tempfile
import unittest

from cyberpet.config import Config


class ConfigTests(unittest.TestCase):
    """Validate Config loading and fallback behavior."""

    def tearDown(self) -> None:
        Config.reset()

    def test_invalid_toml_falls_back_to_defaults(self) -> None:
        """Malformed TOML must not crash config loading."""
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write("[general\npet_name = 'broken'\n")
            bad_path = tmp.name

        try:
            config = Config.load(bad_path)
            self.assertEqual(config.general.pet_name, "Byte")
            self.assertEqual(
                config.general.get("event_stream_socket"),
                "/var/run/cyberpet_events.sock",
            )
            self.assertEqual(config.general.get("event_stream_socket_mode"), "0660")
            self.assertEqual(config.terminal_guard.get("socket_mode"), "0660")
            self.assertEqual(config.ui.get("show_allowed_events"), False)
        finally:
            os.unlink(bad_path)

    def test_valid_toml_is_loaded(self) -> None:
        """A valid TOML file should override defaults."""
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(
                "\n".join(
                    [
                        "[general]",
                        'pet_name = "Nova"',
                        'log_level = "DEBUG"',
                        'event_stream_socket = "/tmp/custom_events.sock"',
                        "",
                        "[terminal_guard]",
                        "enabled = true",
                        'socket_path = "/tmp/custom_guard.sock"',
                        "block_threshold = 61",
                        "hard_block_threshold = 86",
                        'allow_override_phrase = "CYBERPET ALLOW"',
                        "",
                        "[ui]",
                        'pet_name = "Nova"',
                        "refresh_rate_ms = 500",
                    ]
                )
            )
            good_path = tmp.name

        try:
            config = Config.load(good_path)
            self.assertEqual(config.general.pet_name, "Nova")
            self.assertEqual(config.general.event_stream_socket, "/tmp/custom_events.sock")
            self.assertEqual(config.terminal_guard.socket_path, "/tmp/custom_guard.sock")
        finally:
            os.unlink(good_path)

    def test_thresholds_are_sanitized_when_invalid(self) -> None:
        """Thresholds must remain ordered and within safe bounds."""
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(
                "\n".join(
                    [
                        "[terminal_guard]",
                        "block_threshold = 10",
                        "hard_block_threshold = 5",
                    ]
                )
            )
            path = tmp.name

        try:
            config = Config.load(path)
            self.assertGreater(config.terminal_guard.block_threshold, 30)
            self.assertGreater(
                config.terminal_guard.hard_block_threshold,
                config.terminal_guard.block_threshold,
            )
        finally:
            os.unlink(path)

    def test_partial_config_inherits_missing_v2_sections(self) -> None:
        """Loading partial TOML should still expose V2 sections via fallback merge."""
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(
                "\n".join(
                    [
                        "[general]",
                        'pet_name = "Mini"',
                        "",
                        "[terminal_guard]",
                        "block_threshold = 61",
                        "hard_block_threshold = 86",
                    ]
                )
            )
            path = tmp.name

        try:
            config = Config.load(path)
            self.assertEqual(config.general.pet_name, "Mini")
            self.assertEqual(config.scanner.get("quick_scan_interval_minutes"), 30)
            self.assertEqual(config.hash_db.get("db_path"), "/var/lib/cyberpet/hashes.db")
            self.assertEqual(config.yara.get("scan_timeout_seconds"), 30)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
