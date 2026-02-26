"""Tests for socket permission parsing helpers."""

from __future__ import annotations

import os
import tempfile
import unittest

from cyberpet.socket_security import apply_socket_permissions, parse_socket_mode


class SocketSecurityTests(unittest.TestCase):
    """Validate mode parsing and safe permission application."""

    def test_parse_socket_mode_from_string(self) -> None:
        self.assertEqual(parse_socket_mode("0660"), 0o660)
        self.assertEqual(parse_socket_mode("660"), 0o660)
        self.assertEqual(parse_socket_mode("0o660"), 0o660)

    def test_parse_socket_mode_from_int(self) -> None:
        self.assertEqual(parse_socket_mode(0o640), 0o640)
        self.assertEqual(parse_socket_mode(660), 0o660)

    def test_parse_socket_mode_invalid_fallback(self) -> None:
        self.assertEqual(parse_socket_mode("invalid", default=0o600), 0o600)
        self.assertEqual(parse_socket_mode(9999, default=0o600), 0o600)

    def test_apply_permissions_handles_missing_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sock")
            with open(path, "w", encoding="utf-8") as f:
                f.write("x")

            apply_socket_permissions(path, "0660", "group_that_does_not_exist_12345", "tests")
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o660)


if __name__ == "__main__":
    unittest.main()
