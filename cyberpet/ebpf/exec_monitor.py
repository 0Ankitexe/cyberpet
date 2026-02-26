"""eBPF-based process execution monitor for CyberPet V2."""

from __future__ import annotations

import asyncio
import os
import time
from threading import Thread
from typing import Any

from cyberpet.events import Event, EventBus, EventType
from cyberpet.logger import log_info, log_warn

# BCC is optional — degrade gracefully
try:
    from bcc import BPF  # type: ignore[import]
    _BCC_AVAILABLE = True
except ImportError:
    _BCC_AVAILABLE = False

# BPF C program (tracepoint path)
_TRACEPOINT_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
    char args[384];
    s32 retval;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), args->filename);
    event.retval = 0;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

# BPF C program (kprobe fallback path)
_KPROBE_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
    char args[384];
    s32 retval;
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);
    event.retval = -1;  // unknown on entry probe

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


class ExecMonitor:
    """eBPF-based kernel process execution monitor.

    Attaches to the ``sched_process_exec`` tracepoint to capture
    every process execution, publishing events to the CyberPet EventBus.

    Falls back gracefully if BCC is missing, the kernel is too old,
    or the process lacks root privileges.

    Usage:
        monitor = ExecMonitor(event_bus)
        await monitor.start()   # starts in background thread
        await monitor.stop()
    """

    def __init__(self, event_bus: EventBus, config: Any | None = None) -> None:
        self.event_bus = event_bus
        self.config = config
        self._bpf: Any = None
        self._thread: Thread | None = None
        self._running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._attach_mode = ""

    @property
    def available(self) -> bool:
        """Check if eBPF monitoring is available."""
        if self.config is not None and not bool(self.config.get("enabled", True)):
            return False
        if not _BCC_AVAILABLE:
            return False
        if os.geteuid() != 0:
            return False
        return True

    async def start(self) -> bool:
        """Start the eBPF process monitor.

        Returns:
            True if started successfully, False if degraded.
        """
        if self.config is not None and not bool(self.config.get("enabled", True)):
            log_info("eBPF exec monitor disabled by config", module="exec_monitor")
            return False

        if not _BCC_AVAILABLE:
            log_warn(
                "BCC not installed — eBPF exec monitor disabled. "
                "Install with: apt install bcc python3-bpfcc",
                module="exec_monitor",
            )
            return False

        if os.geteuid() != 0:
            log_warn(
                "Not running as root — eBPF exec monitor disabled",
                module="exec_monitor",
            )
            return False

        if not self._start_with_tracepoint():
            if not self._start_with_kprobe():
                self._bpf = None
                self._attach_mode = ""
                return False

        self._running = True
        self._loop = asyncio.get_event_loop()
        self._thread = Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        log_info(f"eBPF exec monitor started ({self._attach_mode})", module="exec_monitor")
        return True

    def _start_with_tracepoint(self) -> bool:
        """Attempt tracepoint mode (preferred)."""
        try:
            self._bpf = BPF(text=_TRACEPOINT_BPF_PROGRAM)
            self._bpf["events"].open_perf_buffer(self._handle_event_raw)
            self._attach_mode = "tracepoint:sched_process_exec"
            return True
        except Exception as exc:
            log_warn(
                f"Tracepoint attach failed ({exc}); trying kprobe fallback",
                module="exec_monitor",
            )
            self._bpf = None
            return False

    def _start_with_kprobe(self) -> bool:
        """Attempt kprobe fallback mode when tracepoint fails."""
        try:
            self._bpf = BPF(text=_KPROBE_BPF_PROGRAM)
            attach_errors: list[str] = []
            for event_name in ("__x64_sys_execve", "sys_execve"):
                try:
                    self._bpf.attach_kprobe(event=event_name, fn_name="trace_execve")
                    self._attach_mode = f"kprobe:{event_name}"
                    break
                except Exception as exc:
                    attach_errors.append(f"{event_name}: {exc}")
            if not self._attach_mode:
                raise RuntimeError("; ".join(attach_errors))
            self._bpf["events"].open_perf_buffer(self._handle_event_raw)
            return True
        except Exception as exc:
            log_warn(
                f"kprobe fallback failed — exec monitor disabled: {exc}",
                module="exec_monitor",
            )
            self._bpf = None
            self._attach_mode = ""
            return False

    async def stop(self) -> None:
        """Stop the eBPF monitor and clean up."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self._bpf:
            try:
                self._bpf.cleanup()
            except Exception:
                pass
            self._bpf = None
        log_info("eBPF exec monitor stopped", module="exec_monitor")

    def _poll_loop(self) -> None:
        """Background thread: poll BPF perf buffer."""
        while self._running and self._bpf:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except Exception:
                if self._running:
                    time.sleep(0.1)

    def _handle_event_raw(self, cpu: int, data: Any, size: int) -> None:
        """Callback invoked by BCC for each exec event."""
        if not self._running or not self._bpf:
            return
        try:
            event = self._bpf["events"].event(data)
            args_raw = getattr(event, "args", b"")
            args = ""
            if isinstance(args_raw, (bytes, bytearray)):
                args = args_raw.decode("utf-8", errors="replace").rstrip("\x00")
            if not args:
                args = self._read_proc_args(int(event.pid))
            self._publish_event(
                pid=event.pid,
                ppid=event.ppid,
                uid=event.uid,
                comm=event.comm.decode("utf-8", errors="replace").rstrip("\x00"),
                filename=event.filename.decode("utf-8", errors="replace").rstrip("\x00"),
                args=args,
                retval=int(getattr(event, "retval", 0)),
            )
        except Exception:
            pass

    @staticmethod
    def _read_proc_args(pid: int) -> str:
        """Read first three argv values from /proc for richer event context."""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read(4096)
            if not raw:
                return ""
            parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00") if p]
            if not parts:
                return ""
            return " ".join(parts[:3])[:384]
        except OSError:
            return ""

    def _publish_event(
        self,
        pid: int,
        ppid: int,
        uid: int,
        comm: str,
        filename: str,
        args: str,
        retval: int,
    ) -> None:
        """Bridge exec event from thread to asyncio event loop."""
        if not self._loop or not self._running:
            return
        event = Event(
            type=EventType.EVENT_EXEC,
            source="exec_monitor",
            data={
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "comm": comm,
                "filename": filename,
                "args": args,
                "retval": retval,
            },
        )
        asyncio.run_coroutine_threadsafe(
            self.event_bus.publish(event), self._loop
        )
