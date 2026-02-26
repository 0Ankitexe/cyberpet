"""Helpers for secure unix socket permissions."""

from __future__ import annotations

import grp
import os
from typing import Any

from cyberpet.logger import log_warn  # type: ignore[import]


def parse_socket_mode(mode_value: Any, default: int = 0o660) -> int:
    """Parse a socket mode value from config.

    Accepts int values (e.g. 0o660, 660) and octal-like strings
    (e.g. "0660", "660", "0o660").
    """
    if isinstance(mode_value, int):
        if 0 <= mode_value <= 0o777:
            return mode_value
        if 0 <= mode_value <= 777:
            try:
                parsed = int(str(mode_value), 8)
                if 0 <= parsed <= 0o777:
                    return parsed
            except ValueError:
                return default
        return default

    if isinstance(mode_value, str):
        text = mode_value.strip().lower()
        if text.startswith("0o"):
            text = text[2:]
        if text.startswith("0") and len(text) > 1:
            text = text[1:]
        if text and all(ch in "01234567" for ch in text):
            try:
                parsed = int(text, 8)
                if 0 <= parsed <= 0o777:
                    return parsed
            except ValueError:
                return default

    return default


def apply_socket_permissions(
    socket_path: str,
    mode_value: Any,
    group_name: str | None,
    module: str,
) -> None:
    """Apply socket chmod/chgrp with safe fallbacks."""
    mode = parse_socket_mode(mode_value, default=0o660)
    os.chmod(socket_path, mode)

    if not group_name:
        return

    try:
        gid = grp.getgrnam(group_name).gr_gid
        os.chown(socket_path, -1, gid)
    except KeyError:
        log_warn(
            f"Socket group '{group_name}' does not exist. Keeping default group.",
            module=module,
        )
    except PermissionError:
        log_warn(
            f"Insufficient permission to assign group '{group_name}' to socket.",
            module=module,
        )
    except OSError as exc:
        log_warn(f"Failed to set socket group '{group_name}': {exc}", module=module)
