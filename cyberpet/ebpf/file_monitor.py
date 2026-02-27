"""fanotify-based file access monitor for CyberPet V2.

Uses Linux fanotify with permission events to intercept and
optionally block file access on sensitive system paths.

Degrades gracefully when fanotify is unavailable or the process
lacks root privileges.
"""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import os
import struct
import time
from threading import Thread
from typing import Any

from cyberpet.events import Event, EventBus, EventType
from cyberpet.logger import log_info, log_warn

# fanotify constants
FAN_CLOEXEC = 0x00000001
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020

FAN_ACCESS = 0x00000001
FAN_OPEN = 0x00000020
FAN_OPEN_PERM = 0x00010000
FAN_ACCESS_PERM = 0x00020000
FAN_CLOSE_WRITE = 0x00000008

FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010

FAN_ALLOW = 0x01
FAN_DENY = 0x02

# fanotify_event_metadata
FANOTIFY_METADATA_VERSION = 3
FAN_EVENT_METADATA_LEN = 24  # size of struct fanotify_event_metadata

# struct fanotify_response
FANOTIFY_RESPONSE_FMT = "=iI"  # int fd, unsigned int response
FANOTIFY_RESPONSE_SIZE = struct.calcsize(FANOTIFY_RESPONSE_FMT)

# Try to load libc
_libc = None
_FANOTIFY_AVAILABLE = False
try:
    _libc_name = ctypes.util.find_library("c")
    if _libc_name:
        _libc = ctypes.CDLL(_libc_name, use_errno=True)
        _FANOTIFY_AVAILABLE = True
except Exception:
    pass

_PACKAGE_MANAGERS = frozenset({"apt", "apt-get", "dpkg", "dnf", "yum", "rpm"})
_SUDO_EDITORS = frozenset({"sudo", "visudo"})


class FileAccessMonitor:
    """fanotify-based file access monitor.

    Monitors sensitive system paths and blocks suspicious access
    patterns using Linux fanotify permission events.

    Usage:
        monitor = FileAccessMonitor(event_bus, config)
        await monitor.start()
        await monitor.stop()
    """

    def __init__(
        self,
        event_bus: EventBus,
        monitored_paths: list[str] | None = None,
        whitelist: list[str] | None = None,
        permission_mode: bool = False,
    ) -> None:
        self.event_bus = event_bus
        self.monitored_paths = monitored_paths or [
            "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/lib"
        ]
        self.whitelist = frozenset(whitelist or [
            "apt", "apt-get", "dpkg", "dnf", "yum", "rpm",
            "pip", "pip3", "systemd", "systemctl", "sshd",
            "cron", "rsyslog",
        ])
        self.whitelist = frozenset(name.lower() for name in self.whitelist)
        # permission_mode=True uses FAN_*_PERM and can block filesystem access.
        # Keep this opt-in to avoid host stalls from misbehaving user-space monitors.
        self.permission_mode = bool(permission_mode)
        self._fan_fd: int = -1
        self._thread: Thread | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None

    @property
    def available(self) -> bool:
        """Check if fanotify is usable."""
        if not _FANOTIFY_AVAILABLE or not _libc:
            return False
        if os.geteuid() != 0:
            return False
        return True

    async def start(self) -> bool:
        """Start the fanotify file access monitor.

        Returns:
            True if started, False if degraded.
        """
        if not _FANOTIFY_AVAILABLE or not _libc:
            log_warn(
                "fanotify not available — file access monitor disabled",
                module="file_monitor",
            )
            return False

        if os.geteuid() != 0:
            log_warn(
                "Not running as root — file access monitor disabled",
                module="file_monitor",
            )
            return False

        class_flag = FAN_CLASS_CONTENT if self.permission_mode else FAN_CLASS_NOTIF
        event_mask = (FAN_OPEN_PERM | FAN_ACCESS_PERM) if self.permission_mode else (FAN_OPEN | FAN_CLOSE_WRITE)

        try:
            self._fan_fd = _libc.fanotify_init(
                FAN_CLOEXEC | class_flag | FAN_UNLIMITED_QUEUE,
                os.O_RDONLY | os.O_LARGEFILE,
            )
            if self._fan_fd < 0:
                errno = ctypes.get_errno()
                log_warn(f"fanotify_init failed (errno={errno}) — file monitor disabled", module="file_monitor")
                return False
        except Exception as exc:
            log_warn(f"fanotify_init exception: {exc} — file monitor disabled", module="file_monitor")
            return False

        # Mark monitored paths
        for path in self.monitored_paths:
            if not os.path.exists(path):
                continue
            try:
                ret = _libc.fanotify_mark(
                    self._fan_fd,
                    FAN_MARK_ADD | FAN_MARK_MOUNT,
                    event_mask,
                    -1,
                    path.encode("utf-8"),
                )
                if ret < 0:
                    log_warn(f"fanotify_mark failed for {path}", module="file_monitor")
            except Exception:
                pass

        self._running = True
        self._loop = asyncio.get_event_loop()
        self._thread = Thread(target=self._read_loop, daemon=True)
        self._thread.start()
        log_info(
            f"File access monitor started on {len(self.monitored_paths)} paths "
            f"(mode={'enforce' if self.permission_mode else 'observe'})",
            module="file_monitor",
        )
        return True

    async def stop(self) -> None:
        """Stop the fanotify monitor."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._fan_fd >= 0:
            try:
                os.close(self._fan_fd)
            except OSError:
                pass
            self._fan_fd = -1
        log_info("File access monitor stopped", module="file_monitor")

    def _read_loop(self) -> None:
        """Background thread: read fanotify events and respond."""
        buf_size = 4096
        while self._running and self._fan_fd >= 0:
            try:
                buf = os.read(self._fan_fd, buf_size)
            except OSError:
                if self._running:
                    time.sleep(0.1)
                continue

            offset = 0
            while offset + FAN_EVENT_METADATA_LEN <= len(buf):
                # Parse fanotify_event_metadata
                event_len, vers, _, mask, fd, pid = struct.unpack_from(
                    "=IbbHiI", buf, offset
                )
                # The actual struct is: uint32 event_len, uint8 vers, uint8 reserved,
                # uint16 metadata_len, uint64 mask, int32 fd, int32 pid
                # Re-parse correctly:
                event_len = struct.unpack_from("=I", buf, offset)[0]
                mask_val = struct.unpack_from("=Q", buf, offset + 8)[0]
                fd_val = struct.unpack_from("=i", buf, offset + 16)[0]
                pid_val = struct.unpack_from("=i", buf, offset + 20)[0]

                if event_len < FAN_EVENT_METADATA_LEN:
                    break

                if fd_val >= 0:
                    self._handle_permission_event(fd_val, pid_val, mask_val)

                offset += event_len

    def _handle_permission_event(self, fd: int, pid: int, mask: int) -> None:
        """Decide whether to allow or deny an access."""
        # Get target file path from fd
        try:
            target_path = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            target_path = "<unknown>"

        # Get process info
        process_name = self._get_process_name(pid)
        process_path = self._get_process_path(pid)
        write_access = self._is_write_access(fd)
        access_type = "open" if (mask & (FAN_OPEN_PERM | FAN_OPEN)) else "access"
        is_permission_event = bool(mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM))

        # Decision logic
        decision, reason, event_type, severity = self._evaluate_access(
            process_name,
            process_path,
            target_path,
            write_access,
        )

        if is_permission_event:
            # Write response only for permission events.
            try:
                response = struct.pack(FANOTIFY_RESPONSE_FMT, fd, decision)
                os.write(self._fan_fd, response)
            except OSError:
                pass

        # Close the event fd
        try:
            os.close(fd)
        except OSError:
            pass

        # Publish event if blocked or suspicious
        if event_type is not None:
            self._publish_event(
                pid, process_name, process_path, target_path,
                "deny" if decision == FAN_DENY else "allow",
                reason,
                event_type,
                severity,
                access_type,
            )

    def _evaluate_access(
        self,
        process_name: str,
        process_path: str,
        target_path: str,
        write_access: bool,
    ) -> tuple[int, str, EventType | None, int]:
        """Evaluate file access against block/suspicious policies."""
        pname = process_name.strip()
        lname = pname.lower()

        if lname in self.whitelist:
            return FAN_ALLOW, "", None, 0

        # Whitelist CyberPet's own processes — the daemon runs from /opt/cyberpet/
        # and legitimately needs to read system files for scanning.
        # NOTE: do NOT whitelist /usr/bin/python here — that would allow any
        # arbitrary Python script to bypass the shadow/sudoers deny rules.
        _TRUSTED_PROCESS_PATHS = (
            "/opt/cyberpet/",
        )
        if any(process_path.startswith(p) for p in _TRUSTED_PROCESS_PATHS):
            return FAN_ALLOW, "", None, 0

        if process_path.startswith(("/tmp", "/dev/shm")):
            if target_path in {"/etc/passwd", "/etc/shadow", "/etc/sudoers"}:
                reason = f"Temp process '{pname}' denied sensitive file access: {target_path}"
                return FAN_DENY, reason, EventType.FILE_ACCESS_BLOCKED, 90
            if target_path.startswith("/etc/"):
                reason = f"Temp process '{pname}' touched protected config: {target_path}"
                return FAN_ALLOW, reason, EventType.FILE_ACCESS_SUSPICIOUS, 45

        if ("python" in lname or "perl" in lname) and target_path == "/etc/shadow":
            reason = f"Interpreter process '{pname}' denied access to /etc/shadow"
            return FAN_DENY, reason, EventType.FILE_ACCESS_BLOCKED, 90

        if target_path == "/etc/sudoers" and lname not in _SUDO_EDITORS:
            reason = f"Non-sudo process '{pname}' denied access to /etc/sudoers"
            return FAN_DENY, reason, EventType.FILE_ACCESS_BLOCKED, 85

        if write_access and target_path.startswith(("/bin/", "/sbin/")) and lname not in _PACKAGE_MANAGERS:
            reason = f"Non-package-manager '{pname}' denied write to system binary path"
            return FAN_DENY, reason, EventType.FILE_ACCESS_BLOCKED, 85

        return FAN_ALLOW, "", None, 0

    @staticmethod
    def _is_write_access(fd: int) -> bool:
        """Inspect fd flags and detect write-intent opens."""
        try:
            with open(f"/proc/self/fdinfo/{fd}", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("flags:"):
                        raw = line.split(":", 1)[1].strip()
                        flags = int(raw, 8)
                        access_mode = flags & os.O_ACCMODE
                        return access_mode in (os.O_WRONLY, os.O_RDWR)
        except (OSError, ValueError):
            return False
        return False

    @staticmethod
    def _get_process_name(pid: int) -> str:
        """Get process name from /proc."""
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except OSError:
            return "<unknown>"

    @staticmethod
    def _get_process_path(pid: int) -> str:
        """Get process executable path from /proc."""
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return "<unknown>"

    def _publish_event(
        self,
        pid: int,
        process_name: str,
        process_path: str,
        target_path: str,
        decision: str,
        reason: str,
        event_type: EventType,
        severity: int,
        access_type: str,
    ) -> None:
        """Bridge file access event to asyncio event loop."""
        if not self._loop or not self._running:
            return
        event = Event(
            type=event_type,
            source="file_monitor",
            data={
                "pid": pid,
                "process_name": process_name,
                "process_path": process_path,
                "target_path": target_path,
                "access_type": access_type,
                "decision": decision,
                "reason": reason,
            },
            severity=severity,
        )
        asyncio.run_coroutine_threadsafe(
            self.event_bus.publish(event), self._loop
        )
