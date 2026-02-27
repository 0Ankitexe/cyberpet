"""eBPF-based syscall anomaly monitor for CyberPet V3.

Monitors raw syscalls via tracepoint for 5 anomaly types:
  - PTRACE_ABUSE: Suspicious ptrace attach from non-debugger
  - FORK_BOMB: clone/fork rate > 100/s per PID
  - MEMFD_MALWARE: memfd_create for fileless malware
  - MMAP_EXEC: mmap with PROT_EXEC (shellcode injection)
  - PERSONA_TRICK: setuid/setgid from non-root (privilege escalation)

Degrades gracefully when BCC is unavailable or not running as root.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import time
from threading import Thread
from typing import Any

from cyberpet.events import Event, EventBus, EventType

logger = logging.getLogger("cyberpet.syscall_monitor")

# BCC is optional — degrade gracefully
try:
    from bcc import BPF  # type: ignore[import]
    _BCC_AVAILABLE = True
except ImportError:
    _BCC_AVAILABLE = False

# ── Syscall numbers (x86_64) ───────────────────────────────────────────
SYS_CLONE = 56
SYS_PTRACE = 101
SYS_SETUID = 105
SYS_SETGID = 106
SYS_MMAP = 9
SYS_MEMFD_CREATE = 319

# ptrace request codes
PTRACE_ATTACH = 16

# mmap protection flags
PROT_EXEC = 0x4

# Thresholds
FORK_BOMB_THRESHOLD = 100  # clones per second per PID

# BPF program: trace raw_syscalls/sys_enter
_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct syscall_event_t {
    u32 pid;
    u32 uid;
    u64 syscall_nr;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    char comm[16];
};

BPF_PERF_OUTPUT(syscall_events);

// Filter: only emit events for syscalls we care about
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 nr = args->id;

    // Only monitor specific syscalls
    if (nr != 56  &&   // clone
        nr != 101 &&   // ptrace
        nr != 105 &&   // setuid
        nr != 106 &&   // setgid
        nr != 9   &&   // mmap
        nr != 319) {   // memfd_create
        return 0;
    }

    struct syscall_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.syscall_nr = nr;
    event.arg0 = args->args[0];
    event.arg1 = args->args[1];
    event.arg2 = args->args[2];
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    syscall_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class SyscallAnomalyMonitor:
    """eBPF syscall anomaly detector for CyberPet V3.

    Monitors raw syscalls and detects 5 anomaly categories,
    publishing SYSCALL_ANOMALY events to the EventBus.

    Usage:
        monitor = SyscallAnomalyMonitor(event_bus, config)
        await monitor.start()
        await monitor.stop()
    """

    def __init__(self, event_bus: EventBus, config: Any = None) -> None:
        self._bus = event_bus
        self._config = config or {}
        self._bpf: Any = None
        self._thread: Thread | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None

        # Per-PID clone counters: pid → deque of timestamps
        self._clone_counts: dict[int, collections.deque] = {}

        # Overall anomaly score (0.0 - 1.0)
        self._anomaly_score = 0.0
        self._anomaly_count = 0

    @property
    def available(self) -> bool:
        if not _BCC_AVAILABLE:
            return False
        if os.geteuid() != 0:
            return False
        return True

    @property
    def anomaly_score(self) -> float:
        return self._anomaly_score

    async def start(self) -> bool:
        """Start the eBPF syscall monitor.

        Returns True if started, False if degraded.
        """
        if not _BCC_AVAILABLE:
            logger.warning(
                "BCC not installed — syscall monitor disabled. "
                "Install with: apt install bcc python3-bpfcc"
            )
            return False

        if os.geteuid() != 0:
            logger.warning("Not running as root — syscall monitor disabled")
            return False

        try:
            self._bpf = BPF(text=_BPF_PROGRAM)
            self._bpf["syscall_events"].open_perf_buffer(self._handle_raw)
        except Exception as exc:
            logger.warning(f"Failed to attach syscall monitor: {exc}")
            self._bpf = None
            return False

        self._running = True
        self._loop = asyncio.get_event_loop()
        self._thread = Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("Syscall anomaly monitor started (tracepoint:raw_syscalls)")
        return True

    async def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None
        logger.info("Syscall anomaly monitor stopped")

    def _poll_loop(self) -> None:
        """Background thread polling perf buffer."""
        while self._running and self._bpf:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                if self._running:
                    continue
                break

    def _handle_raw(self, cpu: int, data: Any, size: int) -> None:
        """Process raw perf buffer event from BPF."""
        if not self._bpf:
            return

        event = self._bpf["syscall_events"].event(data)
        pid = event.pid
        uid = event.uid
        nr = event.syscall_nr
        comm = event.comm.decode("utf-8", errors="replace")

        now = time.time()

        # ── T030: PTRACE_ABUSE ──
        if nr == SYS_PTRACE and event.arg0 == PTRACE_ATTACH:
            self._publish_anomaly(
                category="PTRACE_ABUSE",
                severity=90,
                pid=pid, uid=uid, comm=comm,
                detail=f"ptrace ATTACH from {comm} (PID {pid})",
            )

        # ── T031: FORK_BOMB ──
        elif nr == SYS_CLONE:
            self._check_fork_bomb(pid, uid, comm, now)

        # ── T032: MEMFD_MALWARE ──
        elif nr == SYS_MEMFD_CREATE:
            self._publish_anomaly(
                category="MEMFD_MALWARE",
                severity=85,
                pid=pid, uid=uid, comm=comm,
                detail=f"memfd_create by {comm} (PID {pid}) — fileless malware indicator",
            )

        # ── T032: MMAP_EXEC ──
        elif nr == SYS_MMAP and (event.arg2 & PROT_EXEC):
            self._publish_anomaly(
                category="MMAP_EXEC",
                severity=70,
                pid=pid, uid=uid, comm=comm,
                detail=f"mmap with PROT_EXEC by {comm} (PID {pid})",
            )

        # ── T033: PERSONA_TRICK ──
        elif nr in (SYS_SETUID, SYS_SETGID) and uid != 0:
            syscall_name = "setuid" if nr == SYS_SETUID else "setgid"
            self._publish_anomaly(
                category="PERSONA_TRICK",
                severity=80,
                pid=pid, uid=uid, comm=comm,
                detail=f"{syscall_name} from non-root {comm} (UID {uid}, PID {pid})",
            )

    def _check_fork_bomb(
        self, pid: int, uid: int, comm: str, now: float
    ) -> None:
        """T031: Detect clone() rate > threshold per PID per second."""
        if pid not in self._clone_counts:
            self._clone_counts[pid] = collections.deque(maxlen=200)

        window = self._clone_counts[pid]
        window.append(now)

        # Count clones in the last second
        cutoff = now - 1.0
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) > FORK_BOMB_THRESHOLD:
            self._publish_anomaly(
                category="FORK_BOMB",
                severity=95,
                pid=pid, uid=uid, comm=comm,
                detail=f"Fork bomb: {len(window)} clones/s from {comm} (PID {pid})",
            )
            # Reset to avoid flooding
            window.clear()

    def _publish_anomaly(
        self,
        category: str,
        severity: int,
        pid: int,
        uid: int,
        comm: str,
        detail: str,
    ) -> None:
        """Publish SYSCALL_ANOMALY event to EventBus."""
        self._anomaly_count += 1
        # Decay anomaly score slowly
        self._anomaly_score = min(1.0, self._anomaly_score + 0.1)

        event = Event(
            type=EventType.SYSCALL_ANOMALY,
            source="syscall_monitor",
            data={
                "category": category,
                "pid": pid,
                "uid": uid,
                "comm": comm,
                "detail": detail,
                "anomaly_count": self._anomaly_count,
            },
            severity=severity,
        )

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(
                asyncio.ensure_future, self._bus.publish(event)
            )
        else:
            logger.warning(f"ANOMALY (no loop): {detail}")

    def decay_score(self, amount: float = 0.01) -> None:
        """Decay the anomaly score (called periodically from main loop)."""
        self._anomaly_score = max(0.0, self._anomaly_score - amount)
