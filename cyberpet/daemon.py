"""CyberPet daemon — main entry point.

Orchestrates the EventBus, TerminalGuard, V2 kernel monitors,
scan scheduler, system stats collector, and graceful shutdown handling.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import time

import psutil  # type: ignore[import]

from cyberpet.config import Config  # type: ignore[import]
from cyberpet.events import Event, EventBus, EventType  # type: ignore[import]
from cyberpet.logger import log_info, log_warn, log_error, log_threat, setup_logging  # type: ignore[import]
from cyberpet.socket_security import apply_socket_permissions  # type: ignore[import]
from cyberpet.state import PetState  # type: ignore[import]
from cyberpet.terminal_guard import TerminalGuard  # type: ignore[import]


# Default path for the event stream socket (TUI connects here)
EVENT_STREAM_SOCKET = "/var/run/cyberpet_events.sock"


class EventStreamServer:
    """Broadcasts EventBus events to connected TUI processes via a unix socket.

    Each event is sent as a single JSON line so the TUI can reconstruct
    Event objects and update its display in real time, even though the
    daemon and TUI are separate OS processes.
    """

    def __init__(
        self,
        event_bus: EventBus,
        socket_path: str = EVENT_STREAM_SOCKET,
        socket_mode: str | int = "0660",
        socket_group: str = "cyberpet",
    ) -> None:
        self.event_bus = event_bus
        self.socket_path = socket_path
        self.socket_mode = socket_mode
        self.socket_group = socket_group
        self._server: asyncio.AbstractServer | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self._broadcast_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the event stream server."""
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self.socket_path
        )
        apply_socket_permissions(
            self.socket_path,
            self.socket_mode,
            self.socket_group,
            module="daemon",
        )
        log_info(f"Event stream server listening on {self.socket_path}", module="daemon")
        self._broadcast_task = asyncio.create_task(self._broadcast())

    async def stop(self) -> None:
        """Stop the event stream server."""
        if self._server:
            from typing import cast as _cast
            srv = _cast(asyncio.AbstractServer, self._server)
            srv.close()
            await srv.wait_closed()
        if self._broadcast_task:
            self._broadcast_task.cancel()
            await asyncio.gather(self._broadcast_task, return_exceptions=True)
            self._broadcast_task = None
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Keep the connection open until the client disconnects."""
        self._writers.append(writer)
        log_info(f"TUI client connected (clients={len(self._writers)})", module="daemon")
        try:
            await reader.read()  # block until client closes
        finally:
            if writer in self._writers:
                self._writers.remove(writer)
            log_info(f"TUI client disconnected (clients={len(self._writers)})", module="daemon")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _broadcast(self) -> None:
        """Subscribe to EventBus and push every event to all connected TUI clients."""
        try:
            async for event in self.event_bus.subscribe():
                if not self._writers:
                    continue
                line = json.dumps({
                    "type": event.type.value,
                    "source": event.source,
                    "data": event.data,
                    "severity": event.severity,
                    "timestamp": event.timestamp.isoformat(),
                }) + "\n"
                dead: list[asyncio.StreamWriter] = []
                for writer in self._writers:
                    try:
                        writer.write(line.encode())
                        await writer.drain()
                    except Exception:
                        dead.append(writer)
                for w in dead:
                    if w in self._writers:
                        self._writers.remove(w)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log_error(f"Event stream broadcast failed: {exc}", module="daemon")


class CyberPetDaemon:
    """The main CyberPet daemon.

    Orchestrates all subsystems: event bus, terminal guard,
    system stats collector, and signal handling.

    Usage:
        daemon = CyberPetDaemon()
        asyncio.run(daemon.start())
    """

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize the daemon.

        Args:
            config_path: Optional explicit path to config file.
        """
        self.config = Config.load(config_path)
        self.event_bus = EventBus()
        self.pet_state = PetState()
        self.terminal_guard: TerminalGuard | None = None
        self._event_stream: EventStreamServer | None = None
        self._exec_monitor = None
        self._file_monitor = None
        self._scan_scheduler = None
        self._rl_engine = None
        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._start_time = 0.0

    async def start(self) -> None:
        """Start the daemon and all subsystems.

        1. Load config
        2. Set up logger
        3. Write PID file
        4. Create EventBus
        5. Create shared PetState
        6. Start TerminalGuard as async task
        7. Start system stats collector
        8. Handle SIGTERM/SIGINT gracefully
        """
        self._running = True
        self._start_time = time.time()

        # Set up logging
        log_level = self.config.general.get("log_level", "INFO")
        log_path = self.config.general.get("log_path", "/var/log/cyberpet/")
        setup_logging(log_path=log_path, log_level=log_level)

        log_info("CyberPet daemon starting...", module="daemon")

        # Write PID file
        pid_file = self.config.general.get("pid_file", "/var/run/cyberpet.pid")
        self._write_pid_file(pid_file)

        # Set up signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(self.stop(s)))

        # Start TerminalGuard
        if self.config.terminal_guard.get("enabled", True):
            try:
                self.terminal_guard = TerminalGuard(self.config, self.event_bus)
                await self.terminal_guard.start()
                log_info("Terminal guard started", module="daemon")
            except Exception as exc:
                log_error(f"Failed to start terminal guard: {exc}", module="daemon")

        # Start event stream server (TUI connects here)
        try:
            stream_socket = self.config.general.get("event_stream_socket", EVENT_STREAM_SOCKET)
            stream_socket_mode = self.config.general.get("event_stream_socket_mode", "0660")
            stream_socket_group = self.config.general.get("event_stream_socket_group", "cyberpet")
            self._event_stream = EventStreamServer(
                self.event_bus,
                stream_socket,
                socket_mode=stream_socket_mode,
                socket_group=stream_socket_group,
            )
            await self._event_stream.start()
        except Exception as exc:
            log_error(f"Failed to start event stream server: {exc}", module="daemon")
            self._event_stream = None

        # Start system stats collector
        stats_task = asyncio.create_task(self._stats_collector())
        self._tasks.append(stats_task)

        # Start event-to-logger subscriber
        logger_task = asyncio.create_task(self._event_logger())
        self._tasks.append(logger_task)

        # Start uptime tracker
        uptime_task = asyncio.create_task(self._uptime_tracker())
        self._tasks.append(uptime_task)

        # ── V2 Module Startup ─────────────────────────────────────────

        # Start eBPF exec monitor (degrades gracefully)
        try:
            from cyberpet.ebpf.exec_monitor import ExecMonitor
            if self.config.exec_monitor.get("enabled", True):
                self._exec_monitor = ExecMonitor(self.event_bus, self.config.exec_monitor)
                started = await self._exec_monitor.start()
                if started:
                    log_info("eBPF exec monitor started", module="daemon")
        except Exception as exc:
            log_warn(f"eBPF exec monitor unavailable: {exc}", module="daemon")
            self._exec_monitor = None

        # Start fanotify file monitor (degrades gracefully)
        try:
            from cyberpet.ebpf.file_monitor import FileAccessMonitor
            monitored = self.config.file_monitor.get("monitored_paths",
                ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/lib"])
            whitelist = self.config.file_monitor.get("whitelist", [])
            if self.config.file_monitor.get("enabled", True):
                self._file_monitor = FileAccessMonitor(self.event_bus, monitored, whitelist)
                started = await self._file_monitor.start()
                if started:
                    log_info("File access monitor started", module="daemon")
        except Exception as exc:
            log_warn(f"File access monitor unavailable: {exc}", module="daemon")
            self._file_monitor = None

        # V3: Start syscall anomaly monitor (degrades gracefully)
        self._syscall_monitor = None
        try:
            from cyberpet.ebpf.syscall_monitor import SyscallAnomalyMonitor
            self._syscall_monitor = SyscallAnomalyMonitor(self.event_bus, self.config.rl)
            started = await self._syscall_monitor.start()
            if started:
                log_info("Syscall anomaly monitor started", module="daemon")
            else:
                self._syscall_monitor = None
        except Exception as exc:
            log_warn(f"Syscall anomaly monitor unavailable: {exc}", module="daemon")
            self._syscall_monitor = None

        # ── V3: Initialize shared FP memory and scan history ────────
        fp_memory = None
        scan_history = None
        try:
            from cyberpet.false_positive_memory import FalsePositiveMemory
            from cyberpet.scan_history import ScanHistory
            fp_memory = FalsePositiveMemory()
            scan_history = ScanHistory()
            log_info("FP memory and scan history loaded", module="daemon")
        except Exception as exc:
            log_warn(f"FP memory/scan history unavailable: {exc}", module="daemon")

        # Start scan scheduler (with fp_memory if available)
        try:
            from cyberpet.scan_scheduler import ScanScheduler
            self._scan_scheduler = ScanScheduler(
                self.config, self.event_bus, self.pet_state,
                fp_memory=fp_memory,
            )
            await self._scan_scheduler.start()
            log_info("Scan scheduler started", module="daemon")
        except Exception as exc:
            log_error(f"Failed to start scan scheduler: {exc}", module="daemon")
            self._scan_scheduler = None

        # ── V3: RL Brain Initialization ────────────────────────────────
        if self.config.rl.get("enabled", False) and fp_memory and scan_history:
            try:
                from cyberpet.state_collector import SystemStateCollector
                from cyberpet.rl_prior import RLPriorKnowledge
                from cyberpet.action_executor import ActionExecutor
                from cyberpet.rl_env import CyberPetEnv
                from cyberpet.rl_engine import RLEngine

                # State collector (subscribes to events)
                state_collector = SystemStateCollector(self.event_bus, self.pet_state)
                await state_collector.start()

                # Prior knowledge
                prior = RLPriorKnowledge(fp_memory, scan_history)

                # Action executor
                vault = getattr(self._scan_scheduler, 'quarantine', None)
                action_executor = ActionExecutor(
                    self.event_bus, vault, fp_memory, prior, self.pet_state,
                )

                # Gymnasium environment
                env = CyberPetEnv(
                    state_collector, action_executor, fp_memory, prior, self.config,
                )

                # RL Engine
                self._rl_engine = RLEngine(
                    self.config, self.event_bus, fp_memory, scan_history,
                )
                self._rl_engine.initialize()
                self._rl_engine.set_env(env)

                # Update pet state
                self.pet_state.rl_state = (
                    "WARMUP" if self._rl_engine.is_warmup else "TRAINING"
                )

                # Start RL loop and FP event listener
                rl_task = asyncio.create_task(self._rl_loop())
                self._tasks.append(rl_task)
                fp_task = asyncio.create_task(self._fp_event_listener())
                self._tasks.append(fp_task)

                log_info(
                    f"RL engine initialized (warmup: {self._rl_engine.warmup_remaining} steps)",
                    module="daemon",
                )
            except ImportError as exc:
                log_warn(f"RL dependencies not available: {exc}", module="daemon")
                self.pet_state.rl_state = "DISABLED"
            except Exception as exc:
                log_error(f"RL engine initialization failed: {exc}", module="daemon")
                self.pet_state.rl_state = "DISABLED"
        else:
            if not self.config.rl.get("enabled", False):
                log_info("RL engine disabled by config", module="daemon")
            self.pet_state.rl_state = "DISABLED"

        log_info(f"CyberPet daemon started (PID: {os.getpid()})", module="daemon")

        # Wait until stopped
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

        log_info("CyberPet daemon stopped", module="daemon")

    async def stop(self, sig: signal.Signals | None = None) -> None:
        """Gracefully stop the daemon.

        Args:
            sig: The signal that triggered the stop (or None).
        """
        if not self._running:
            return

        sig_name = sig.name if sig else "manual"
        log_info(f"Shutting down (signal: {sig_name})...", module="daemon")
        self._running = False

        # Save RL model on shutdown
        if self._rl_engine:
            try:
                self._rl_engine.shutdown()
                log_info("RL engine shut down and model saved", module="daemon")
            except Exception as exc:
                log_error(f"Error saving RL model: {exc}", module="daemon")

        # Stop V2 modules
        if self._scan_scheduler:
            try:
                await self._scan_scheduler.stop()
            except Exception as exc:
                log_error(f"Error stopping scan scheduler: {exc}", module="daemon")

        if self._exec_monitor:
            try:
                await self._exec_monitor.stop()
            except Exception as exc:
                log_error(f"Error stopping exec monitor: {exc}", module="daemon")

        if self._file_monitor:
            try:
                await self._file_monitor.stop()
            except Exception as exc:
                log_error(f"Error stopping file monitor: {exc}", module="daemon")

        # Stop terminal guard
        if self.terminal_guard:
            try:
                await self.terminal_guard.stop()
            except Exception as exc:
                log_error(f"Error stopping terminal guard: {exc}", module="daemon")

        # Stop event stream server
        if self._event_stream:
            try:
                await self._event_stream.stop()
            except Exception as exc:
                log_error(f"Error stopping event stream server: {exc}", module="daemon")

        # Cancel all tasks
        for task in self._tasks:
            task.cancel()

        # Wait for tasks to finish
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        # Remove PID file
        pid_file = self.config.general.get("pid_file", "/var/run/cyberpet.pid")
        self._remove_pid_file(pid_file)

    async def _stats_collector(self) -> None:
        """Collect system stats every 5 seconds and publish events."""
        try:
            while self._running:
                cpu = psutil.cpu_percent(interval=None)
                ram = psutil.virtual_memory().percent

                self.pet_state.cpu_percent = cpu
                self.pet_state.ram_percent = ram

                await self.event_bus.publish(Event(
                    type=EventType.SYSTEM_STAT_UPDATE,
                    source="daemon",
                    data={"cpu": cpu, "ram": ram},
                    severity=0,
                ))

                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass

    async def _uptime_tracker(self) -> None:
        """Track daemon uptime."""
        try:
            while self._running:
                self.pet_state.uptime_seconds = int(time.time() - self._start_time)
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    async def _rl_loop(self) -> None:
        """Run RL decision cycle every N seconds (V3)."""
        interval = self.config.rl.get("decision_interval_seconds", 30)
        model_dir = self.config.rl.get("model_path", "/var/lib/cyberpet/models/")
        state_file = os.path.join(model_dir, "rl_state.json")
        try:
            while self._running and self._rl_engine:
                step_info = self._rl_engine.run_step()

                # Update pet state
                self.pet_state.rl_steps_trained = self._rl_engine.total_steps
                self.pet_state.rl_last_action = step_info.get("action_name", "")
                self.pet_state.rl_avg_reward = self._rl_engine.avg_reward
                details = step_info.get("details", {})
                self.pet_state.rl_last_confidence = details.get(
                    "confidence", 0.0
                ) if isinstance(details, dict) else 0.0
                self.pet_state.rl_state = (
                    "WARMUP" if self._rl_engine.is_warmup else "TRAINING"
                )

                # Write rl_state.json for CLI `model status` command
                try:
                    import json as _json
                    _json.dump(
                        {
                            "total_steps": self._rl_engine.total_steps,
                            "avg_reward": round(self._rl_engine.avg_reward, 4),
                            "rl_state": self.pet_state.rl_state,
                            "last_action": step_info.get("action_name", ""),
                            "warmup_remaining": self._rl_engine.warmup_remaining,
                        },
                        open(state_file, "w"),
                    )
                except Exception:
                    pass

                # Publish RL_DECISION event
                await self.event_bus.publish(Event(
                    type=EventType.RL_DECISION,
                    source="rl_engine",
                    data=step_info,
                    severity=0,
                ))

                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    async def _fp_event_listener(self) -> None:
        """Subscribe to FP_MARKED_SAFE events and forward to RL engine (V3)."""
        try:
            async for event in self.event_bus.subscribe():
                if event.type == EventType.FP_MARKED_SAFE and self._rl_engine:
                    sha256 = event.data.get("sha256", "")
                    filepath = event.data.get("filepath", "")
                    if sha256 or filepath:
                        self._rl_engine.handle_fp_marked_safe(sha256, filepath)
        except asyncio.CancelledError:
            pass

    async def _event_logger(self) -> None:
        """Subscribe to all events and write them to the structured log.

        Routes THREAT_DETECTED events to the separate threat log.
        """
        try:
            async for event in self.event_bus.subscribe():
                cmd = event.data.get("command", "")
                reason = event.data.get("reason", "")
                score = event.data.get("score", "")

                msg = f"[{event.type.value}] "
                if cmd:
                    msg += f"cmd='{cmd[:80]}' "
                if reason:
                    msg += f"reason='{reason}' "
                if score:
                    msg += f"score={score}"

                log_info(msg.strip(), module=event.source)

                if event.type == EventType.THREAT_DETECTED:
                    log_threat(
                        f"{cmd[:80]} — {reason} (score: {score})",
                        module=event.source,
                    )
        except asyncio.CancelledError:
            pass

    def _write_pid_file(self, pid_file: str) -> None:
        """Write the current PID to a file.

        Handles stale PID detection: if the PID file exists but the
        process is not running, we clean up and proceed.

        Args:
            pid_file: Path to the PID file.
        """
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    old_pid = int(f.read().strip())
                # Check if process is still running
                if psutil.pid_exists(old_pid):
                    log_error(
                        f"CyberPet daemon already running (PID: {old_pid})",
                        module="daemon",
                    )
                    sys.exit(1)
                else:
                    log_warn(f"Stale PID file found (PID {old_pid} not running), cleaning up",
                             module="daemon")
                    os.unlink(pid_file)
            except (ValueError, OSError):
                os.unlink(pid_file)

        os.makedirs(os.path.dirname(pid_file), exist_ok=True)
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))

    @staticmethod
    def _remove_pid_file(pid_file: str) -> None:
        """Remove the PID file.

        Args:
            pid_file: Path to the PID file.
        """
        try:
            if os.path.exists(pid_file):
                os.unlink(pid_file)
        except OSError:
            pass


def start_ui(
    event_bus: EventBus | None = None,
    pet_state: PetState | None = None,
    config_path: str | None = None,
) -> None:
    """Launch the CyberPet TUI.

    Can be run in a separate terminal while the daemon runs
    in the background.

    Args:
        event_bus: EventBus to connect to (None for standalone demo).
        pet_state: Shared PetState (None creates local).
        config_path: Optional config path.
    """
    from cyberpet.ui.pet import CyberPetApp  # type: ignore[import]

    config = Config.load(config_path)
    pet_name = config.ui.get("pet_name", "Byte")
    event_stream_socket = config.general.get("event_stream_socket", EVENT_STREAM_SOCKET)
    show_allowed_events = bool(config.ui.get("show_allowed_events", False))

    app = CyberPetApp(
        event_bus=event_bus,
        pet_state=pet_state,
        pet_name=pet_name,
        event_stream_socket=event_stream_socket,
        show_allowed_events=show_allowed_events,
    )
    app.run()
