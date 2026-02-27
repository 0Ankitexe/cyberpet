"""System state collector for CyberPet V3 RL brain.

Builds the 44-feature observation vector from system metrics, EventBus
events, and PetState.  Features are normalised to [0, 1] for the PPO model.
"""

from __future__ import annotations

import asyncio
import math
import os
import time
from collections import deque
from typing import TYPE_CHECKING

import numpy as np
import psutil  # type: ignore[import]

from cyberpet.events import Event, EventBus, EventType

if TYPE_CHECKING:
    from cyberpet.state import PetState

# ── Constants ──────────────────────────────────────────────────────────
STATE_DIM = 44

# Sliding-window size for threat history (indices 22-29)
_THREAT_HISTORY_LEN = 8

# Rolling window for FP rate calculation
_FP_WINDOW_SCANS = 5


class SystemStateCollector:
    """Collect and normalise the 44-feature state vector.

    Groups
    ------
    0-5   : CPU / Memory
    6-11  : Process activity
    12-16 : Network
    17-21 : File system
    22-29 : Threat history (sliding window)
    30-36 : Security events
    37-41 : Time context
    42-43 : Scan quality metrics

    The collector subscribes to the EventBus and keeps running counters
    that are snapshotted on demand by ``collect()``.
    """

    def __init__(self, event_bus: EventBus, pet_state: PetState) -> None:
        self._bus = event_bus
        self._pet = pet_state

        # ── Accumulators (updated by events) ──────────────────────────
        self._cmd_blocked_hour: deque[float] = deque()
        self._cmd_warned_hour: deque[float] = deque()
        self._exec_blocks_hour: deque[float] = deque()
        self._new_proc_events: deque[float] = deque()
        self._new_conn_events: deque[float] = deque()
        self._etc_mod_events: deque[float] = deque()
        self._home_mod_events: deque[float] = deque()
        self._cron_modified = False

        # Threat history sliding window
        self._threat_scores: deque[float] = deque(
            [0.0] * _THREAT_HISTORY_LEN, maxlen=_THREAT_HISTORY_LEN
        )

        # Scan quality metrics
        self._pkg_verified_ratio: float = 0.0
        self._fp_count_recent: int = 0
        self._threats_flagged_recent: int = 0
        self._scans_counted: int = 0

        # CPU history for 1/5/15 min avg (update with psutil on collect)
        self._anomaly_score: float = 0.0

        # Network I/O baseline
        self._last_net_io = psutil.net_io_counters()
        self._last_net_time = time.monotonic()

        # Disk I/O baseline
        self._last_disk_io = psutil.disk_io_counters()
        self._last_disk_time = time.monotonic()

        # Subscriber task
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start listening to EventBus events."""
        self._task = asyncio.create_task(self._listen())

    async def stop(self) -> None:
        """Cancel the listener task."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ── Public API ─────────────────────────────────────────────────────

    def collect(self) -> np.ndarray:
        """Return the current 44-feature state vector as float32 in [0, 1]."""
        vec = np.zeros(STATE_DIM, dtype=np.float32)
        now = time.time()

        # ── Group 1: CPU / Memory (0-5) ──
        load1, load5, load15 = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        vec[0] = _clip(load1 / cpu_count)            # cpu_percent_1min
        vec[1] = _clip(load5 / cpu_count)            # cpu_percent_5min
        vec[2] = _clip(load15 / cpu_count)           # cpu_percent_15min
        mem = psutil.virtual_memory()
        vec[3] = mem.percent / 100.0                  # ram_percent
        swap = psutil.swap_memory()
        vec[4] = swap.percent / 100.0                 # swap_percent
        vec[5] = self._disk_io_rate()                 # disk_io_rate

        # ── Group 2: Process activity (6-11) ──
        procs = list(psutil.process_iter(["status", "uids"]))
        vec[6] = _clip(len(procs) / 1000.0)                   # process_count
        vec[7] = _clip(self._count_recent(self._new_proc_events, now) / 100.0)
        root_cnt = sum(1 for p in procs if _is_root(p))
        vec[8] = _clip(root_cnt / 200.0)                       # root_process_count
        vec[9] = _clip(0.0)                                     # unknown_process_count (placeholder)
        zombie = sum(1 for p in procs if _is_zombie(p))
        vec[10] = _clip(zombie / 50.0)                          # zombie_count
        try:
            threads = sum(p.num_threads() for p in procs if p.is_running())
        except Exception:
            threads = 0
        vec[11] = _clip(threads / 5000.0)                       # thread_count

        # ── Group 3: Network (12-16) ──
        conns = psutil.net_connections(kind="inet")
        vec[12] = _clip(len(conns) / 1000.0)                   # connection_count
        vec[13] = self._outbound_rate()                          # outbound_bytes_rate
        vec[14] = _clip(self._count_recent(self._new_conn_events, now) / 100.0)
        external = sum(1 for c in conns if c.raddr and not _is_local(c.raddr))
        vec[15] = _clip(external / 500.0)                       # external_connection_count
        failed = sum(1 for c in conns if c.status == "CLOSE_WAIT")
        vec[16] = _clip(failed / 100.0)                         # failed_connection_count

        # ── Group 4: File system (17-21) ──
        vec[17] = _clip(self._count_recent(self._etc_mod_events, now) / 50.0)
        vec[18] = _clip(self._count_tmp_files() / 1000.0)       # tmp_file_count
        vec[19] = _clip(self._count_tmp_executables() / 100.0)  # tmp_executable_count
        vec[20] = 1.0 if self._cron_modified else 0.0            # cron_modification_flag
        vec[21] = _clip(self._count_recent(self._home_mod_events, now) / 100.0)

        # ── Group 5: Threat history (22-29) ──
        for i, score in enumerate(self._threat_scores):
            vec[22 + i] = _clip(score / 100.0)

        # ── Group 6: Security events (30-36) ──
        vec[30] = _clip(self._count_recent(self._cmd_blocked_hour, now) / 50.0)
        vec[31] = _clip(self._count_recent(self._cmd_warned_hour, now) / 100.0)
        vec[32] = _clip(self._pet.files_quarantined / 50.0)
        vec[33] = _clip(self._count_recent(self._exec_blocks_hour, now) / 50.0)
        vec[34] = _clip(self._pet.last_scan_threats_found / 20.0)
        vec[35] = _clip(self._anomaly_score)
        vec[36] = _clip(self._pet.files_quarantined / 50.0)     # quarantine_count_active

        # ── Group 7: Time context (37-41) ──
        import datetime as _dt
        dt_now = _dt.datetime.now()
        h = dt_now.hour + dt_now.minute / 60.0
        d = dt_now.weekday()
        vec[37] = (math.sin(2 * math.pi * h / 24.0) + 1.0) / 2.0
        vec[38] = (math.cos(2 * math.pi * h / 24.0) + 1.0) / 2.0
        vec[39] = (math.sin(2 * math.pi * d / 7.0) + 1.0) / 2.0
        vec[40] = (math.cos(2 * math.pi * d / 7.0) + 1.0) / 2.0
        vec[41] = 1.0 if 9 <= dt_now.hour < 17 and d < 5 else 0.0

        # ── Group 8: Scan quality (42-43) ──
        vec[42] = _clip(self._pkg_verified_ratio)
        vec[43] = _clip(self._fp_rate_recent())

        return vec

    def update_anomaly_score(self, score: float) -> None:
        """Called externally by syscall monitor."""
        self._anomaly_score = max(0.0, min(1.0, score))

    # ── Event listener ─────────────────────────────────────────────────

    async def _listen(self) -> None:
        """Process incoming EventBus events."""
        async for event in self._bus.subscribe():
            now = time.time()
            try:
                self._handle_event(event, now)
            except Exception:
                pass

    def _handle_event(self, event: Event, now: float) -> None:
        """Dispatch event to appropriate handler."""
        etype = event.type

        if etype == EventType.CMD_BLOCKED:
            self._cmd_blocked_hour.append(now)
        elif etype == EventType.CMD_WARNED:
            self._cmd_warned_hour.append(now)
        elif etype == EventType.EVENT_EXEC:
            self._new_proc_events.append(now)
        elif etype == EventType.FILE_ACCESS_BLOCKED:
            self._exec_blocks_hour.append(now)
        elif etype == EventType.FILE_ACCESS_SUSPICIOUS:
            path = event.data.get("filepath", "")
            if path.startswith("/etc/"):
                self._etc_mod_events.append(now)
            elif path.startswith("/home/"):
                self._home_mod_events.append(now)
            if "cron" in path:
                self._cron_modified = True
        elif etype == EventType.QUARANTINE_SUCCESS:
            score = event.data.get("threat_score", 0)
            self._threat_scores.append(float(score))
        elif etype == EventType.SCAN_COMPLETE:
            data = event.data
            scanned = data.get("files_scanned", 0)
            verified = data.get("skipped_pkg_verified", 0)
            if scanned > 0:
                self._pkg_verified_ratio = verified / scanned
            threats = data.get("threats_found", 0)
            if isinstance(threats, int):
                self._threats_flagged_recent += threats
            self._scans_counted += 1
            scan_threats = data.get("threats_found_count", threats)
            self._threat_scores.append(float(scan_threats))
        elif etype == EventType.FP_MARKED_SAFE:
            self._fp_count_recent += 1
        elif etype == EventType.SYSCALL_ANOMALY:
            severity = event.data.get("severity", 50) / 100.0
            self._anomaly_score = min(1.0, self._anomaly_score + severity * 0.3)

    # ── Helpers ────────────────────────────────────────────────────────

    def _count_recent(self, dq: deque[float], now: float, window: float = 3600.0) -> int:
        """Count events in the deque within the last ``window`` seconds."""
        cutoff = now - window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _disk_io_rate(self) -> float:
        now = time.monotonic()
        try:
            cur = psutil.disk_io_counters()
            dt = max(now - self._last_disk_time, 0.01)
            read_rate = (cur.read_bytes - self._last_disk_io.read_bytes) / dt
            write_rate = (cur.write_bytes - self._last_disk_io.write_bytes) / dt
            self._last_disk_io = cur
            self._last_disk_time = now
            return _clip((read_rate + write_rate) / 1e8)
        except Exception:
            return 0.0

    def _outbound_rate(self) -> float:
        now = time.monotonic()
        try:
            cur = psutil.net_io_counters()
            dt = max(now - self._last_net_time, 0.01)
            rate = (cur.bytes_sent - self._last_net_io.bytes_sent) / dt
            self._last_net_io = cur
            self._last_net_time = now
            return _clip(rate / 1e8)
        except Exception:
            return 0.0

    def _fp_rate_recent(self) -> float:
        if self._threats_flagged_recent == 0:
            return 0.0
        return min(1.0, self._fp_count_recent / self._threats_flagged_recent)

    @staticmethod
    def _count_tmp_files() -> int:
        try:
            return len(os.listdir("/tmp"))
        except OSError:
            return 0

    @staticmethod
    def _count_tmp_executables() -> int:
        count = 0
        try:
            for entry in os.scandir("/tmp"):
                if entry.is_file() and os.access(entry.path, os.X_OK):
                    count += 1
        except OSError:
            pass
        return count


# ── Module-level helpers ──────────────────────────────────────────────

def _clip(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def _is_root(proc: psutil.Process) -> bool:
    try:
        uids = proc.uids()
        return uids.real == 0 if uids else False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def _is_zombie(proc: psutil.Process) -> bool:
    try:
        return proc.status() == psutil.STATUS_ZOMBIE
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def _is_local(addr) -> bool:
    if not addr:
        return True
    ip = addr.ip if hasattr(addr, "ip") else str(addr[0])
    return ip.startswith("127.") or ip == "::1" or ip == "0.0.0.0"
