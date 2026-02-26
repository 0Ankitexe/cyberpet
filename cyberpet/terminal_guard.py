"""Terminal Guard — Unix domain socket server for command interception.

Listens on a unix socket for commands from the shell hook, scores them
for danger, and responds with ALLOW/WARN/BLOCK per the socket protocol.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import socket
import struct
import time
import uuid
from datetime import datetime
from typing import cast

from cyberpet.cmd_scorer import DangerScorer, ScoringContext  # type: ignore[import]
from cyberpet.config import Config  # type: ignore[import]
from cyberpet.events import Event, EventBus, EventType  # type: ignore[import]
from cyberpet.logger import log_info, log_warn, log_error, log_threat  # type: ignore[import]
from cyberpet.socket_security import apply_socket_permissions  # type: ignore[import]


class TerminalGuard:
    """Command interception server.

    Creates a unix domain socket and listens for incoming command strings
    from the shell hook. Each command is scored and the appropriate
    action (ALLOW/WARN/BLOCK) is returned.

    Supports an override mechanism: if a command is blocked, the user
    can send the configured override phrase to allow it through.

    Attributes:
        config: Application configuration.
        event_bus: The central event bus for publishing events.
        scorer: The danger scoring engine.
    """

    def __init__(self, config: Config, event_bus: EventBus) -> None:
        """Initialize the terminal guard.

        Args:
            config: Application configuration.
            event_bus: The event bus for publishing events.
        """
        self.config = config
        self.event_bus = event_bus
        self.scorer = DangerScorer()
        self._server: asyncio.AbstractServer | None = None

        # Per-connection pending overrides: maps writer id -> (command, score, reason, token)
        self._pending_overrides: dict[int, tuple[str, int, str, str]] = {}
        # Token-based override cache: token -> (command, score, reason, expiry_monotonic)
        self._token_overrides: dict[str, tuple[str, int, str, float]] = {}
        # Failed override attempts per token.
        self._token_override_failures: dict[str, int] = {}
        self._override_token_ttl_seconds = 120.0
        max_failures_raw = self.config.terminal_guard.get("override_max_failures", 3)
        try:
            max_failures = int(max_failures_raw)
        except (TypeError, ValueError):
            max_failures = 3
        self._override_max_failures = max(1, max_failures)
        self._next_connection_id = 1

    @staticmethod
    def _parse_request(
        raw: str,
    ) -> tuple[str, str | None, int | None, str | None, str | None]:
        """Parse a request line.

        Supports both legacy plain-text commands and JSON payloads:
          {"command": "...", "cwd": "...", "hour_of_day": 0-23}
          {"override_token": "...", "override_phrase": "..."}
        """
        raw = raw.strip()
        if not raw:
            return "", None, None, None, None

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return raw, None, None, None, None

        if not isinstance(payload, dict):
            return raw, None, None, None, None

        cwd = payload.get("cwd")
        if not isinstance(cwd, str):
            cwd = None

        hour_of_day = payload.get("hour_of_day")
        if not isinstance(hour_of_day, int):
            hour_of_day = None

        override_token = payload.get("override_token")
        if not isinstance(override_token, str):
            override_token = None

        override_phrase = payload.get("override_phrase")
        if not isinstance(override_phrase, str):
            override_phrase = None

        if override_token and override_phrase is not None:
            return "", cwd, hour_of_day, override_token.strip(), override_phrase

        command = payload.get("command")
        if not isinstance(command, str):
            return "", cwd, hour_of_day, None, None

        return command.strip(), cwd, hour_of_day, None, None

    def _prune_expired_tokens(self) -> None:
        """Remove expired override tokens."""
        now = time.monotonic()
        expired = [
            token
            for token, (_cmd, _score, _reason, expiry) in self._token_overrides.items()
            if now >= expiry
        ]
        for token in expired:
            self._token_overrides.pop(token, None)
            self._token_override_failures.pop(token, None)

    def _clear_pending_by_token(self, token: str) -> None:
        """Remove per-writer pending override entries for a token."""
        stale_writers = [
            writer_id
            for writer_id, (_cmd, _score, _reason, pending_token) in self._pending_overrides.items()
            if pending_token == token
        ]
        for writer_id in stale_writers:
            self._pending_overrides.pop(writer_id, None)

    def _allocate_connection_id(self) -> int:
        """Allocate a monotonic connection id for override tracking."""
        connection_id = self._next_connection_id
        self._next_connection_id += 1
        return connection_id

    def _register_override_failure(self, token: str) -> bool:
        """Track override failures; return True when token should be locked/burned."""
        failures = self._token_override_failures.get(token, 0) + 1
        self._token_override_failures[token] = failures
        if failures >= self._override_max_failures:
            self._token_overrides.pop(token, None)
            self._token_override_failures.pop(token, None)
            self._clear_pending_by_token(token)
            return True
        return False

    @staticmethod
    def _get_peer_credentials(writer: asyncio.StreamWriter) -> tuple[int, int, int]:
        """Get peer (pid, uid, gid) via SO_PEERCRED when available."""
        sock = writer.get_extra_info("socket")
        if sock is None:
            # If peer credentials are unavailable, fail to a non-root identity.
            return (0, 65534, 65534)

        try:
            creds = sock.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            pid, uid, gid = struct.unpack("3i", creds)
            return (pid, uid, gid)
        except (AttributeError, OSError, struct.error):
            return (0, 65534, 65534)

    @staticmethod
    def _get_peer_cwd(pid: int) -> str | None:
        """Resolve caller cwd from /proc when pid is available."""
        if pid <= 0:
            return None
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            return None

    async def start(self) -> None:
        """Start the unix socket server.

        Creates the socket at the configured path and begins
        accepting connections.
        """
        socket_path = self.config.terminal_guard.socket_path

        # Remove stale socket file
        if os.path.exists(socket_path):
            os.unlink(socket_path)

        self._server = await asyncio.start_unix_server(
            self._handle_connection,
            path=socket_path,
        )

        socket_mode = self.config.terminal_guard.get("socket_mode", "0660")
        socket_group = self.config.terminal_guard.get("socket_group", "cyberpet")
        apply_socket_permissions(
            socket_path,
            socket_mode,
            socket_group,
            module="terminal_guard",
        )

        log_info(f"Terminal guard listening on {socket_path}", module="terminal_guard")

    async def stop(self) -> None:
        """Stop the socket server and clean up."""
        if self._server:
            server = cast(asyncio.AbstractServer, self._server)
            server.close()
            await server.wait_closed()
            log_info("Terminal guard stopped", module="terminal_guard")

        socket_path = self.config.terminal_guard.socket_path
        if os.path.exists(socket_path):
            os.unlink(socket_path)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection.

        Reads commands, scores them, responds, and handles override
        flow for blocked commands.

        Args:
            reader: Async stream reader for the connection.
            writer: Async stream writer for the connection.
        """
        writer_id = self._allocate_connection_id()
        try:
            while True:
                data = await asyncio.wait_for(reader.readline(), timeout=10.0)
                if not data:
                    break

                self._prune_expired_tokens()
                raw_line = data.decode("utf-8", errors="replace").strip()
                (
                    command,
                    cwd_hint,
                    hour_hint,
                    override_token,
                    override_phrase,
                ) = self._parse_request(raw_line)

                if override_token and override_phrase is not None:
                    token_data = self._token_overrides.get(override_token)
                    if token_data is None:
                        writer.write(b"BLOCK:Override session expired\n")
                        await writer.drain()
                        continue

                    orig_cmd, orig_score, _orig_reason, _expiry = token_data
                    expected_phrase = self.config.terminal_guard.allow_override_phrase
                    if hmac.compare_digest(override_phrase, expected_phrase):
                        self._token_overrides.pop(override_token, None)
                        self._token_override_failures.pop(override_token, None)
                        self._clear_pending_by_token(override_token)
                        writer.write(b"ALLOW\n")
                        await writer.drain()
                        log_warn(
                            f"Override accepted for: {orig_cmd} (was score {orig_score})",
                            module="terminal_guard",
                        )
                        await self.event_bus.publish(Event(
                            type=EventType.CMD_ALLOWED,
                            source="terminal_guard",
                            data={"command": orig_cmd, "override": True, "original_score": orig_score},
                            severity=orig_score,
                        ))
                    else:
                        locked = self._register_override_failure(override_token)
                        if locked:
                            writer.write(b"BLOCK:Override session locked\n")
                        else:
                            writer.write(b"BLOCK:Override phrase required\n")
                        await writer.drain()
                        log_warn(
                            f"Override denied for blocked command: {orig_cmd}",
                            module="terminal_guard",
                        )
                    continue

                if not command:
                    writer.write(b"ALLOW\n")
                    await writer.drain()
                    continue

                # Check if this is an override attempt
                override_phrase = self.config.terminal_guard.allow_override_phrase
                if writer_id in self._pending_overrides:
                    orig_cmd, orig_score, _orig_reason, override_token = self._pending_overrides[writer_id]
                    if hmac.compare_digest(command, override_phrase):
                        self._pending_overrides.pop(writer_id, None)
                        self._token_overrides.pop(override_token, None)
                        self._token_override_failures.pop(override_token, None)
                        writer.write(b"ALLOW\n")
                        await writer.drain()

                        log_warn(
                            f"Override accepted for: {orig_cmd} (was score {orig_score})",
                            module="terminal_guard",
                        )
                        await self.event_bus.publish(Event(
                            type=EventType.CMD_ALLOWED,
                            source="terminal_guard",
                            data={"command": orig_cmd, "override": True, "original_score": orig_score},
                            severity=orig_score,
                        ))
                    else:
                        locked = self._register_override_failure(override_token)
                        if locked:
                            writer.write(b"BLOCK:Override session locked\n")
                        else:
                            writer.write(b"BLOCK:Override phrase required\n")
                        await writer.drain()
                        log_warn(
                            f"Override denied for blocked command: {orig_cmd}",
                            module="terminal_guard",
                        )
                    continue

                # Build scoring context
                peer_pid, peer_uid, _peer_gid = self._get_peer_credentials(writer)
                peer_cwd = self._get_peer_cwd(peer_pid)
                hour_of_day = (
                    hour_hint if isinstance(hour_hint, int) and 0 <= hour_hint <= 23
                    else datetime.now().hour
                )
                context = ScoringContext(
                    is_root=peer_uid == 0,
                    cwd=cwd_hint if cwd_hint else (peer_cwd if peer_cwd else "/"),
                    hour_of_day=hour_of_day,
                )

                # Score the command
                result = self.scorer.score(command, context)

                # Publish interception event
                await self.event_bus.publish(Event(
                    type=EventType.CMD_INTERCEPTED,
                    source="terminal_guard",
                    data={"command": command, "score": result.score, "reason": result.reason},
                    severity=result.score,
                ))

                # Determine action based on thresholds
                block_threshold = self.config.terminal_guard.block_threshold

                if result.score >= block_threshold:
                    # BLOCK
                    override_token = uuid.uuid4().hex[:16]
                    self._token_overrides[override_token] = (
                        command,
                        result.score,
                        result.reason,
                        time.monotonic() + self._override_token_ttl_seconds,
                    )
                    self._token_override_failures[override_token] = 0
                    response = f"BLOCK:{result.reason}|TOKEN:{override_token}\n"
                    writer.write(response.encode("utf-8"))
                    await writer.drain()

                    self._pending_overrides[writer_id] = (
                        command,
                        result.score,
                        result.reason,
                        override_token,
                    )

                    await self.event_bus.publish(Event(
                        type=EventType.CMD_BLOCKED,
                        source="terminal_guard",
                        data={"command": command, "score": result.score, "reason": result.reason},
                        severity=result.score,
                    ))

                    log_threat(f"BLOCKED (score {result.score}): {command} — {result.reason}",
                              module="terminal_guard")

                    # Also publish threat for high scores
                    if result.score >= self.config.terminal_guard.hard_block_threshold:
                        await self.event_bus.publish(Event(
                            type=EventType.THREAT_DETECTED,
                            source="terminal_guard",
                            data={"command": command, "score": result.score, "reason": result.reason},
                            severity=result.score,
                        ))

                elif result.score >= 31:
                    # WARN
                    response = f"WARN:{result.reason}\n"
                    writer.write(response.encode("utf-8"))
                    await writer.drain()

                    await self.event_bus.publish(Event(
                        type=EventType.CMD_WARNED,
                        source="terminal_guard",
                        data={"command": command, "score": result.score, "reason": result.reason},
                        severity=result.score,
                    ))

                    log_warn(f"WARNED (score {result.score}): {command} — {result.reason}",
                             module="terminal_guard")

                else:
                    # ALLOW
                    writer.write(b"ALLOW\n")
                    await writer.drain()

                    await self.event_bus.publish(Event(
                        type=EventType.CMD_ALLOWED,
                        source="terminal_guard",
                        data={"command": command, "score": result.score},
                        severity=result.score,
                    ))

        except asyncio.TimeoutError:
            pass
        except ConnectionResetError:
            pass
        except Exception as exc:
            log_error(f"Connection error: {exc}", module="terminal_guard")
        finally:
            self._pending_overrides.pop(writer_id, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
