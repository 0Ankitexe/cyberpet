#!/usr/bin/env python3
"""Socket client for CyberPet shell hook.

Reads a command from stdin (or first argument), connects to the CyberPet
daemon's unix domain socket, sends the command, and prints the response
to stdout.

Exits with code 0 in all cases — if the daemon is unreachable, the
command is silently allowed through.

Usage:
    echo "rm -rf /" | python3 socket_client.py
    python3 socket_client.py "rm -rf /"
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import sys
from datetime import datetime
from typing import Any, Sequence

SOCKET_PATH = os.environ.get("CYBERPET_SOCKET", "/var/run/cyberpet.sock")
TIMEOUT = 2.0  # seconds


def _build_command_payload(command: str) -> dict[str, Any]:
    """Build a command payload with caller context."""
    return {
        "command": command,
        "cwd": os.environ.get("PWD", os.getcwd()),
        "hour_of_day": datetime.now().hour,
    }


def _build_override_payload(token: str, phrase: str) -> dict[str, Any]:
    """Build a token-based override payload."""
    return {
        "override_token": token,
        "override_phrase": phrase,
    }


def _read_response(sock: socket.socket) -> str:
    """Read a single newline-delimited response from the daemon."""
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        if b"\n" in response:
            break
    return response.decode("utf-8", errors="replace").strip()


def send_lines(lines: Sequence[str], fail_open: bool = True) -> str:
    """Send one or more newline-delimited request lines over one socket.

    Args:
        lines: Raw request lines (without trailing newline).
        fail_open: If True, return ALLOW when daemon is unreachable.
                   If False, return a BLOCK response on transport failure.

    Returns:
        The response to the final request line sent.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(SOCKET_PATH)

            last_response = "ALLOW"
            for line in lines:
                sock.sendall((line + "\n").encode("utf-8"))
                last_response = _read_response(sock)
                if not last_response:
                    return "ALLOW" if fail_open else "BLOCK:Override session failed"
            return last_response
    except (ConnectionRefusedError, FileNotFoundError, socket.timeout):
        return "ALLOW" if fail_open else "BLOCK:Override session failed"
    except OSError as exc:
        if fail_open and exc.errno in (errno.EACCES, errno.EPERM):
            return "WARN:CyberPet socket permission denied; monitoring inactive"
        return "ALLOW" if fail_open else "BLOCK:Override session failed"


def main() -> None:
    """Main entry point.

    Reads command from argument or stdin, sends to daemon, prints response.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--override-token")
    parser.add_argument("--override-phrase")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("command", nargs="*")
    args = parser.parse_args()

    if args.override_token or args.override_phrase:
        if not args.override_token or args.override_phrase is None:
            print("BLOCK:Override session failed")
            sys.exit(0)

        line = json.dumps(_build_override_payload(args.override_token, args.override_phrase))
        response = send_lines([line], fail_open=False)
        print(response)
        sys.exit(0)

    if args.command:
        commands = [" ".join(args.command)]
    else:
        commands = [line.strip() for line in sys.stdin if line.strip()]

    if not commands:
        print("ALLOW")
        sys.exit(0)

    use_json = args.json or os.environ.get("CYBERPET_PROTOCOL", "").strip().lower() == "json"
    if use_json:
        lines = [json.dumps(_build_command_payload(command)) for command in commands if command]
    else:
        lines = [command for command in commands if command]

    # Multi-line mode is used for override flow and should fail closed.
    fail_open = len(commands) == 1
    response = send_lines(lines, fail_open=fail_open)
    print(response)


if __name__ == "__main__":
    main()
