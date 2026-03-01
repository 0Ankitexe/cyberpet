"""Shared helpers for scan trigger-file command transport."""

from __future__ import annotations

import os
from typing import Final

TRIGGER_FILE: Final[str] = "/var/run/cyberpet_scan_trigger"

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore[assignment]


def _lock(file_obj) -> None:
    if fcntl is None:
        return
    fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)


def _unlock(file_obj) -> None:
    if fcntl is None:
        return
    fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def append_trigger_command(command: str, trigger_file: str = TRIGGER_FILE) -> None:
    """Append one scan command to the trigger file."""
    cmd = (command or "").strip().lower()
    if not cmd:
        return

    with open(trigger_file, "a+", encoding="utf-8") as f:
        _lock(f)
        try:
            f.write(cmd + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            _unlock(f)


def read_trigger_commands(
    trigger_file: str = TRIGGER_FILE,
    *,
    clear: bool = False,
) -> list[str]:
    """Read queued trigger commands, optionally clearing the file."""
    with open(trigger_file, "a+", encoding="utf-8") as f:
        _lock(f)
        try:
            f.seek(0)
            raw = f.read()
            if clear:
                f.seek(0)
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())
        finally:
            _unlock(f)

    return [line.strip().lower() for line in raw.splitlines() if line.strip()]
