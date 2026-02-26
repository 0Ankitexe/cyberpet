"""Terminal guard regression tests."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from cyberpet.config import Config
from cyberpet.events import EventBus
from cyberpet.terminal_guard import TerminalGuard


class TerminalGuardTests(unittest.IsolatedAsyncioTestCase):
    """Validate override flow and caller-context handling."""

    async def asyncSetUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self._tmpdir.name, "guard.sock")
        self.config = Config(
            {
                "general": {
                    "pet_name": "Byte",
                    "event_stream_socket": "/tmp/events.sock",
                },
                "terminal_guard": {
                    "enabled": True,
                    "socket_path": self.socket_path,
                    "block_threshold": 61,
                    "hard_block_threshold": 86,
                    "override_max_failures": 3,
                    "allow_override_phrase": "CYBERPET ALLOW",
                },
                "ui": {
                    "refresh_rate_ms": 500,
                    "pet_name": "Byte",
                },
            }
        )
        self.event_bus = EventBus()
        self.guard = TerminalGuard(self.config, self.event_bus)
        await self.guard.start()

    async def asyncTearDown(self) -> None:
        await self.guard.stop()
        self._tmpdir.cleanup()

    async def _send(self, writer: asyncio.StreamWriter, payload: object) -> None:
        if isinstance(payload, str):
            writer.write((payload + "\n").encode("utf-8"))
        else:
            writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()

    async def _recv(self, reader: asyncio.StreamReader) -> str:
        return (await reader.readline()).decode("utf-8", errors="replace").strip()

    async def test_override_requires_exact_phrase(self) -> None:
        """Non-matching override attempts must remain blocked."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._send(writer, {"command": "rm -rf /", "cwd": "/home/zer0", "hour_of_day": 12})
            blocked = await self._recv(reader)
            self.assertTrue(blocked.startswith("BLOCK:"))

            await self._send(writer, {"command": "definitely-not-override", "cwd": "/home/zer0", "hour_of_day": 12})
            denied = await self._recv(reader)
            self.assertEqual(denied, "BLOCK:Override phrase required")

            await self._send(writer, {"command": "CYBERPET ALLOW", "cwd": "/home/zer0", "hour_of_day": 12})
            allowed = await self._recv(reader)
            self.assertEqual(allowed, "ALLOW")
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_scoring_uses_client_context_not_daemon_context(self) -> None:
        """Client CWD/hour hints and non-root peer uid must affect scoring."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            payload = {
                "command": "sudo su",
                "cwd": "/tmp",
                "hour_of_day": 23,
            }
            with patch.object(self.guard, "_get_peer_credentials", return_value=(4242, 1000, 1000)):
                await self._send(writer, payload)
                response = await self._recv(reader)

            self.assertTrue(response.startswith("BLOCK:"))
            self.assertIn("unusual hour (+10)", response)
            self.assertIn("suspicious CWD: /tmp (+10)", response)
            self.assertNotIn("running as root (+15)", response)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_plain_text_request_still_supported(self) -> None:
        """Legacy plain-text command lines should keep working."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._send(writer, "ls -la")
            response = await self._recv(reader)
            self.assertEqual(response, "ALLOW")
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_token_override_avoids_command_replay(self) -> None:
        """Token override should not require replaying/scoring the original command."""
        with patch.object(self.guard.scorer, "score", wraps=self.guard.scorer.score) as mocked_score:
            reader1, writer1 = await asyncio.open_unix_connection(self.socket_path)
            try:
                await self._send(writer1, {"command": "rm -rf /", "cwd": "/home/zer0", "hour_of_day": 12})
                blocked = await self._recv(reader1)
            finally:
                writer1.close()
                await writer1.wait_closed()

            self.assertIn("|TOKEN:", blocked)
            token = blocked.split("|TOKEN:", 1)[1]

            reader2, writer2 = await asyncio.open_unix_connection(self.socket_path)
            try:
                await self._send(
                    writer2,
                    {"override_token": token, "override_phrase": "CYBERPET ALLOW"},
                )
                override_response = await self._recv(reader2)
            finally:
                writer2.close()
                await writer2.wait_closed()

            self.assertEqual(override_response, "ALLOW")
            self.assertEqual(mocked_score.call_count, 1)

    async def test_plain_text_uses_peer_cwd_when_hint_missing(self) -> None:
        """Plain text requests should still include caller cwd context."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            with (
                patch.object(self.guard, "_get_peer_credentials", return_value=(4242, 1000, 1000)),
                patch.object(self.guard, "_get_peer_cwd", return_value="/tmp"),
            ):
                await self._send(writer, "sudo su")
                response = await self._recv(reader)

            self.assertTrue(response.startswith("WARN:") or response.startswith("BLOCK:"))
            self.assertIn("suspicious CWD: /tmp (+10)", response)
            self.assertNotIn("running as root (+15)", response)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_override_token_locks_after_repeated_failures(self) -> None:
        """Token should be burned after configured number of failed attempts."""
        reader1, writer1 = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._send(writer1, {"command": "rm -rf /", "cwd": "/home/zer0", "hour_of_day": 12})
            blocked = await self._recv(reader1)
        finally:
            writer1.close()
            await writer1.wait_closed()

        self.assertIn("|TOKEN:", blocked)
        token = blocked.split("|TOKEN:", 1)[1]

        reader2, writer2 = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._send(
                writer2,
                {"override_token": token, "override_phrase": "nope"},
            )
            denied1 = await self._recv(reader2)
            self.assertEqual(denied1, "BLOCK:Override phrase required")

            await self._send(
                writer2,
                {"override_token": token, "override_phrase": "still-nope"},
            )
            denied2 = await self._recv(reader2)
            self.assertEqual(denied2, "BLOCK:Override phrase required")

            await self._send(
                writer2,
                {"override_token": token, "override_phrase": "wrong-again"},
            )
            locked = await self._recv(reader2)
            self.assertEqual(locked, "BLOCK:Override session locked")

            await self._send(
                writer2,
                {"override_token": token, "override_phrase": "CYBERPET ALLOW"},
            )
            expired = await self._recv(reader2)
            self.assertEqual(expired, "BLOCK:Override session expired")
        finally:
            writer2.close()
            await writer2.wait_closed()

    async def test_expired_token_is_rejected(self) -> None:
        """Token-based override should fail once token ttl has elapsed."""
        self.guard._override_token_ttl_seconds = 0.01

        reader1, writer1 = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._send(writer1, {"command": "rm -rf /", "cwd": "/home/zer0", "hour_of_day": 12})
            blocked = await self._recv(reader1)
        finally:
            writer1.close()
            await writer1.wait_closed()

        self.assertIn("|TOKEN:", blocked)
        token = blocked.split("|TOKEN:", 1)[1]
        await asyncio.sleep(0.05)

        reader2, writer2 = await asyncio.open_unix_connection(self.socket_path)
        try:
            await self._send(
                writer2,
                {"override_token": token, "override_phrase": "CYBERPET ALLOW"},
            )
            response = await self._recv(reader2)
            self.assertEqual(response, "BLOCK:Override session expired")
        finally:
            writer2.close()
            await writer2.wait_closed()

    def test_peer_credentials_fallback_is_non_root(self) -> None:
        """Missing peer credentials should default to non-root identity."""
        class _DummyWriter:
            def get_extra_info(self, _name: str):
                return None

        _pid, uid, _gid = self.guard._get_peer_credentials(_DummyWriter())  # type: ignore[arg-type]
        self.assertEqual(uid, 65534)


if __name__ == "__main__":
    unittest.main()
