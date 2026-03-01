"""Scan scheduler for CyberPet V2.

Orchestrates quick/full scans on a timer and via manual trigger file.
Auto-quarantines high-score threats when configured.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import time
from datetime import datetime, timedelta

from cyberpet.config import Config
from cyberpet.events import Event, EventBus, EventType
from cyberpet.hash_db import HashDatabase
from cyberpet.logger import log_info, log_warn, log_error
from cyberpet.quarantine import QuarantineVault
from cyberpet.scan_history import ScanHistory
from cyberpet.scan_trigger import TRIGGER_FILE, read_trigger_commands
from cyberpet.scanner import CancellationToken, FileScanner
from cyberpet.state import PetState
from cyberpet.yara_engine import YaraEngine


class ScanScheduler:
    """Schedule and trigger file scans.

    - Quick scan on daemon startup (after configurable delay)
    - Quick scan every N minutes (configurable)
    - Full scan daily at configurable time (default 03:00)
    - Manual trigger via trigger file
    - Auto-quarantine for high-score threats

    Usage:
        scheduler = ScanScheduler(config, event_bus, pet_state)
        await scheduler.start()
    """

    def __init__(
        self,
        config: Config,
        event_bus: EventBus,
        pet_state: PetState,
        fp_memory=None,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.pet_state = pet_state

        # Initialize dependencies
        db_path = config.hash_db.get("db_path", "/var/lib/cyberpet/hashes.db")
        seed_file = config.hash_db.get("seed_file", "/etc/cyberpet/seed_hashes.csv")
        rules_dir = config.yara.get("rules_dir", "/etc/cyberpet/rules/")
        scan_timeout = config.yara.get("scan_timeout_seconds", 30)
        vault_path = config.quarantine.get("vault_path", "/var/lib/cyberpet/quarantine/")

        self.hash_db = HashDatabase(db_path)
        # Import seed hashes on first run
        if os.path.exists(seed_file):
            imported = self.hash_db.bulk_import_from_csv(seed_file)
            if imported > 0:
                log_info(f"Imported {imported} seed hashes from {seed_file}", module="scheduler")

        self.yara_engine = YaraEngine(rules_dir, scan_timeout)
        if self.yara_engine.available:
            if self.yara_engine.compile_rules():
                log_info("YARA rules compiled successfully", module="scheduler")
            else:
                log_warn("No YARA rules found or compilation failed", module="scheduler")

        self.scanner = FileScanner(config, event_bus, self.hash_db, self.yara_engine,
                                   fp_memory=fp_memory)
        self.quarantine = QuarantineVault(event_bus, vault_path)
        self.scan_history: ScanHistory | None = None
        try:
            self.scan_history = ScanHistory()
        except Exception as exc:
            log_warn(f"Scan history unavailable: {exc}", module="scheduler")

        # Config
        self._quick_interval = config.scanner.get("quick_scan_interval_minutes", 30) * 60
        self._full_scan_time = config.scanner.get("full_scan_time", "03:00")
        self._auto_quarantine = config.scanner.get("auto_quarantine", False)
        self._auto_quarantine_threshold = config.scanner.get("auto_quarantine_threshold", 80)

        self._tasks: list[asyncio.Task] = []
        self._running = False
        self._scanning = False
        self._pending_quick = False
        self._pending_full = False

        # Scan control — shared with scanner for cancel/pause
        self._cancel_token: CancellationToken | None = None
        self._pause_event: asyncio.Event | None = None  # created in start()
        self._paused: bool = False
        self._cancel_requested: bool = False
        self._deferred_scan_cmd: str | None = None
        self._last_scan_completed: float = 0.0
        self._scan_cooldown: float = 30.0  # min seconds between scans

    def _ensure_pause_event(self) -> asyncio.Event:
        """Lazily initialize pause event for direct unit-test method calls.

        Some tests call `_run_full_scan()` / `_run_quick_scan()` without
        invoking `start()`. In that case `_pause_event` would otherwise be
        `None` and scan tasks can fail/hang before scanner methods run.
        """
        if self._pause_event is None:
            self._pause_event = asyncio.Event()
            self._pause_event.set()
        return self._pause_event

    def _scan_call_kwargs(self, scan_method, pause_event: asyncio.Event) -> dict[str, object]:
        """Build compatible kwargs for scanner methods.

        Keeps compatibility with test fakes and older scanner implementations
        that expose `quick_scan()`/`full_scan()` with no keyword parameters.
        """
        kwargs: dict[str, object] = {}
        try:
            params = inspect.signature(scan_method).parameters
        except (TypeError, ValueError):
            params = {}

        if "cancel_token" in params:
            kwargs["cancel_token"] = self._cancel_token
        if "pause_event" in params:
            kwargs["pause_event"] = pause_event
        return kwargs

    async def start(self) -> None:
        """Start scheduled scanning tasks."""
        self._running = True

        # Create pause event inside the running event loop (not in __init__)
        self._ensure_pause_event()

        # Clear any stale trigger file content from previous session
        # (e.g. RL TRIGGER_SCAN action wrote "quick" before daemon stopped).
        # Must happen synchronously BEFORE the watch task launches.
        try:
            fd = os.open(TRIGGER_FILE, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o666)
            os.close(fd)
            os.chmod(TRIGGER_FILE, 0o666)
        except OSError:
            pass

        # Any rows left in "running" imply daemon/TUI exited mid-scan.
        if self.scan_history:
            try:
                recovered = self.scan_history.cancel_all_running()
                if recovered:
                    log_info(
                        f"Recovered {recovered} stale running scan rows",
                        module="scheduler",
                    )
            except Exception as exc:
                log_warn(f"Scan history recovery failed: {exc}", module="scheduler")

        # Auto-scans disabled — scans only run via manual trigger (TUI or CLI)
        # self._tasks.append(asyncio.create_task(self._startup_scan()))
        # self._tasks.append(asyncio.create_task(self._periodic_quick_scan()))
        # self._tasks.append(asyncio.create_task(self._daily_full_scan()))
        self._track_task(asyncio.create_task(self._watch_trigger()))
        log_info("Scan scheduler started (manual trigger only)", module="scheduler")

    async def stop(self) -> None:
        """Stop all scheduled tasks."""
        self._running = False
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        self.hash_db.close()
        self.quarantine.close()
        if self.scan_history:
            try:
                self.scan_history.close()
            except Exception:
                pass

    def _track_task(self, task: asyncio.Task) -> None:
        """Track a background task and auto-remove it when done."""
        self._tasks.append(task)

        def _cleanup(done: asyncio.Task) -> None:
            try:
                self._tasks.remove(done)
            except ValueError:
                pass

        task.add_done_callback(_cleanup)

    async def _startup_scan(self) -> None:
        """Run quick scan after startup delay."""
        try:
            await asyncio.sleep(30)
            if self._running:
                await self._run_quick_scan()
        except asyncio.CancelledError:
            pass

    async def _periodic_quick_scan(self) -> None:
        """Run quick scan at regular intervals."""
        try:
            # Wait for startup scan to finish first
            await asyncio.sleep(60)
            while self._running:
                await asyncio.sleep(self._quick_interval)
                if self._running:
                    await self._run_quick_scan()
        except asyncio.CancelledError:
            pass

    async def _daily_full_scan(self) -> None:
        """Run full scan once daily at configured time."""
        try:
            while self._running:
                sleep_seconds = self._seconds_until_next_full_scan()
                await asyncio.sleep(sleep_seconds)
                if self._running:
                    await self._run_full_scan()
        except asyncio.CancelledError:
            pass

    def _seconds_until_next_full_scan(self, now: datetime | None = None) -> float:
        """Calculate delay until next configured full scan wall-clock time."""
        if now is None:
            now = datetime.now()
        try:
            hour, minute = str(self._full_scan_time).split(":")
            target_hour, target_minute = int(hour), int(minute)
        except (ValueError, AttributeError):
            target_hour, target_minute = 3, 0

        target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return max(1.0, (target - now).total_seconds())

    async def _watch_trigger(self) -> None:
        """Watch for manual scan trigger file.

        Creates the trigger file path on startup with mode 0666 so unprivileged
        users (running `cyberpet scan quick/full`) can write to it without sudo.
        """
        # Ensure the trigger file exists and is world-writable so any user can
        # drop a scan request without requiring elevated privileges.
        try:
            # Create if missing; always set 0666 so a fresh install works.
            flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
            fd = os.open(TRIGGER_FILE, flags, 0o666)
            os.close(fd)
            os.chmod(TRIGGER_FILE, 0o666)
        except OSError:
            pass  # /var/run may not exist yet — tolerate silently

        try:
            while self._running:
                try:
                    commands = read_trigger_commands(TRIGGER_FILE, clear=True)
                except OSError:
                    commands = []

                for scan_type in commands:
                    await self._handle_trigger_command(scan_type)

                # Keep manual scan controls responsive in TUI/CLI.
                await asyncio.sleep(0.25)
        except asyncio.CancelledError:
            pass

    async def _handle_trigger_command(self, scan_type: str) -> None:
        """Handle a trigger-file command."""
        cmd = (scan_type or "").strip().lower()
        if not cmd:
            return

        if cmd in ("cancel", "stop"):
            if self._scanning:
                log_info("Cancel requested via trigger", module="scheduler")
                self._cancel_requested = True
                self._paused = False
                self._pending_quick = False
                self._pending_full = False
                if self._cancel_token:
                    self._cancel_token.cancel()
                # Unpause so cancel checks can run immediately
                self._ensure_pause_event().set()
            else:
                self._pending_quick = False
                self._pending_full = False
                self._paused = False
                self._cancel_requested = False
                self._deferred_scan_cmd = None
            return

        if cmd == "pause":
            if self._scanning and not self._cancel_requested:
                log_info("Pause requested via trigger", module="scheduler")
                self._paused = True
                self._ensure_pause_event().clear()
            return

        if cmd == "resume":
            if self._scanning and self._paused and not self._cancel_requested:
                log_info("Resume requested via trigger", module="scheduler")
                self._paused = False
                self._ensure_pause_event().set()
            return

        if cmd not in ("full", "quick"):
            return

        # If cancel is in progress, remember one explicit user trigger and run
        # it after cancellation finalizes.
        if self._scanning and self._cancel_requested:
            self._deferred_scan_cmd = cmd
            log_info(
                f"Deferring {cmd} scan until cancel completes",
                module="scheduler",
            )
            return

        if cmd == "full":
            self._track_task(asyncio.create_task(self._run_full_scan()))
        else:
            self._track_task(asyncio.create_task(self._run_quick_scan()))

    async def _run_quick_scan(self) -> None:
        """Execute a quick scan and handle results."""
        if self._scanning:
            if self._cancel_requested:
                log_info("Quick scan ignored (scan cancel in progress)", module="scheduler")
                return
            self._pending_quick = True
            log_info("Quick scan queued (scan already running)", module="scheduler")
            return
        self._scanning = True
        self._cancel_token = CancellationToken()
        pause_event = self._ensure_pause_event()
        pause_event.set()  # reset pause state
        was_cancelled = False
        report = None
        run_id = 0
        started_at = time.time()
        if self.scan_history:
            try:
                run_id = self.scan_history.claim_or_start_scan("quick")
            except Exception as exc:
                log_warn(f"Failed to claim quick-scan history row: {exc}", module="scheduler")
        try:
            log_info("Starting quick scan", module="scheduler")
            report = await self.scanner.quick_scan(**self._scan_call_kwargs(self.scanner.quick_scan, pause_event))
            self.pet_state.last_scan_time = time.time()
            self._last_scan_completed = time.time()
            log_info(
                f"Quick scan complete: {report.files_scanned} files, "
                f"{len(report.threats_found)} threats ({report.scan_duration_seconds:.1f}s)",
                module="scheduler",
            )
            await self._handle_threats(report.threats_found)
        except Exception as exc:
            log_error(f"Quick scan failed: {exc}", module="scheduler")
        finally:
            was_cancelled = bool(self._cancel_token and self._cancel_token.is_cancelled())
            self._scanning = False
            self._paused = False
            self._cancel_token = None
            self._ensure_pause_event().set()

        if self.scan_history and run_id:
            try:
                if was_cancelled or self._cancel_requested or report is None:
                    self.scan_history.cancel_scan(
                        run_id,
                        files_scanned=getattr(report, "files_scanned", 0) if report is not None else 0,
                        threats_found=len(getattr(report, "threats_found", [])) if report is not None else 0,
                        duration_seconds=getattr(
                            report, "scan_duration_seconds", max(0.0, time.time() - started_at)
                        ),
                    )
                else:
                    self.scan_history.complete_scan(
                        run_id,
                        files_scanned=getattr(report, "files_scanned", 0),
                        threats_found=len(getattr(report, "threats_found", [])),
                        duration_seconds=getattr(
                            report, "scan_duration_seconds", max(0.0, time.time() - started_at)
                        ),
                    )
            except Exception as exc:
                log_warn(f"Failed to finalize quick-scan history row: {exc}", module="scheduler")

        if was_cancelled or self._cancel_requested:
            self._pending_quick = False
            self._pending_full = False
            self._cancel_requested = False
            log_info("Quick scan cancelled", module="scheduler")
            if self._deferred_scan_cmd and self._running:
                deferred = self._deferred_scan_cmd
                self._deferred_scan_cmd = None
                if deferred == "full":
                    self._track_task(asyncio.create_task(self._run_full_scan()))
                else:
                    self._track_task(asyncio.create_task(self._run_quick_scan()))
            return

        await self._drain_queued_scans()

    async def _run_full_scan(self) -> None:
        """Execute a full scan and handle results."""
        if self._scanning:
            if self._cancel_requested:
                log_info("Full scan ignored (scan cancel in progress)", module="scheduler")
                return
            self._pending_full = True
            log_info("Full scan queued (scan already running)", module="scheduler")
            return
        self._scanning = True
        self._cancel_token = CancellationToken()
        pause_event = self._ensure_pause_event()
        pause_event.set()
        was_cancelled = False
        report = None
        run_id = 0
        started_at = time.time()
        if self.scan_history:
            try:
                run_id = self.scan_history.claim_or_start_scan("full")
            except Exception as exc:
                log_warn(f"Failed to claim full-scan history row: {exc}", module="scheduler")
        try:
            log_info("Starting full scan", module="scheduler")
            report = await self.scanner.full_scan(**self._scan_call_kwargs(self.scanner.full_scan, pause_event))
            self.pet_state.last_scan_time = time.time()
            self._last_scan_completed = time.time()
            log_info(
                f"Full scan complete: {report.files_scanned} files, "
                f"{len(report.threats_found)} threats ({report.scan_duration_seconds:.1f}s)",
                module="scheduler",
            )
            await self._handle_threats(report.threats_found)
        except Exception as exc:
            log_error(f"Full scan failed: {exc}", module="scheduler")
        finally:
            was_cancelled = bool(self._cancel_token and self._cancel_token.is_cancelled())
            self._scanning = False
            self._paused = False
            self._cancel_token = None
            self._ensure_pause_event().set()

        if self.scan_history and run_id:
            try:
                if was_cancelled or self._cancel_requested or report is None:
                    self.scan_history.cancel_scan(
                        run_id,
                        files_scanned=getattr(report, "files_scanned", 0) if report is not None else 0,
                        threats_found=len(getattr(report, "threats_found", [])) if report is not None else 0,
                        duration_seconds=getattr(
                            report, "scan_duration_seconds", max(0.0, time.time() - started_at)
                        ),
                    )
                else:
                    self.scan_history.complete_scan(
                        run_id,
                        files_scanned=getattr(report, "files_scanned", 0),
                        threats_found=len(getattr(report, "threats_found", [])),
                        duration_seconds=getattr(
                            report, "scan_duration_seconds", max(0.0, time.time() - started_at)
                        ),
                    )
            except Exception as exc:
                log_warn(f"Failed to finalize full-scan history row: {exc}", module="scheduler")

        if was_cancelled or self._cancel_requested:
            self._pending_quick = False
            self._pending_full = False
            self._cancel_requested = False
            log_info("Full scan cancelled", module="scheduler")
            if self._deferred_scan_cmd and self._running:
                deferred = self._deferred_scan_cmd
                self._deferred_scan_cmd = None
                if deferred == "full":
                    self._track_task(asyncio.create_task(self._run_full_scan()))
                else:
                    self._track_task(asyncio.create_task(self._run_quick_scan()))
            return

        await self._drain_queued_scans()

    async def _drain_queued_scans(self) -> None:
        """Run one queued scan after current scan completes."""
        if not self._running:
            return
        if self._pending_full:
            self._pending_full = False
            await self._run_full_scan()
            return
        if self._pending_quick:
            self._pending_quick = False
            await self._run_quick_scan()

    async def _handle_threats(self, threats: list) -> None:
        """Auto-quarantine high-score threats if configured.

        SAFETY: Only files in /tmp, /dev/shm, /var/tmp can be
        auto-quarantined. Files in user home dirs, app data,
        caches, and system paths are NEVER auto-quarantined.
        """
        # Paths that are safe for automatic quarantine
        _QUARANTINE_SAFE_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")

        for threat in threats:
            self.pet_state.last_threat_name = threat.threat_category
            if (
                self._auto_quarantine
                and threat.threat_score >= self._auto_quarantine_threshold
                and threat.recommended_action == "quarantine"
            ):
                # SAFETY CHECK: never auto-quarantine outside temp dirs
                if not any(threat.filepath.startswith(p) for p in _QUARANTINE_SAFE_PATHS):
                    log_info(
                        f"SKIP auto-quarantine (safe path): {threat.filepath} "
                        f"(score={threat.threat_score})",
                        module="scheduler",
                    )
                    continue

                try:
                    await self.quarantine.quarantine_file(threat.filepath, threat)
                    self.pet_state.files_quarantined += 1
                    log_info(
                        f"Auto-quarantined: {threat.filepath} "
                        f"(score={threat.threat_score}, category={threat.threat_category})",
                        module="scheduler",
                    )
                except Exception as exc:
                    log_error(f"Quarantine failed for {threat.filepath}: {exc}", module="scheduler")
