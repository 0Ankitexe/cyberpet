"""Scan screen for CyberPet TUI.

Architecture:
- Init happens synchronously in on_mount (all constructors are fast)
- Scan runs as asyncio.create_task
- A set_interval timer polls the EventBus queue every 150ms
- All widget updates happen in the main Textual thread
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, ProgressBar, Static
from textual.widgets import ListItem, ListView


# ── Helpers ──────────────────────────────────────────────────────────────────

def _trunc(path: str, n: int = 50) -> str:
    """Truncate a filepath in the middle for display."""
    if len(path) <= n:
        return path
    h = (n - 3) // 2
    return path[:h] + "..." + path[-h:]


def _threat_icon(score: int) -> str:
    if score >= 90:
        return "☠"
    if score >= 70:
        return "🔴"
    return "⚠"


class ScanScreen(Screen):
    """Full scan screen with live progress and threat list."""

    DEFAULT_CSS = """
    /* Dock prev bar to bottom so panels fill remaining space */
    #prev {
        dock: bottom;
        height: 3;
        padding: 0 2;
        border-top: solid $panel;
        color: $text-muted;
        content-align: left middle;
    }

    /* Panels fill all remaining space */
    #panels {
        width: 100%;
        height: 100%;
    }

    /* Left panel: status + controls */
    .left {
        width: 2fr;
        height: 100%;
        border: solid $primary;
        padding: 1;
    }

    /* Right panel: split into files-being-scanned (top) + threats (bottom) */
    .right {
        width: 3fr;
        height: 100%;
        border: solid $warning;
        padding: 1;
    }

    /* Right panel sub-sections */
    #filelog-section {
        height: 1fr;
        border-bottom: solid $panel;
        padding-bottom: 1;
    }
    #filelog-title { text-style: bold; color: $text-muted; margin-bottom: 1; }
    #filelog { height: 1fr; overflow-y: auto; color: $text-muted; }

    #threat-section { height: 1fr; padding-top: 1; }
    #theader { text-style: bold; color: $warning; margin-bottom: 1; }
    #threat-list { height: 1fr; }

    /* Left panel titles */
    .panel-title { text-style: bold; color: $primary; margin-bottom: 1; }

    /* Buttons */
    #start-btn  { width: 100%; margin-top: 1; }
    #cancel-btn { width: 100%; margin-top: 1; }
    #back-btn   { width: 100%; margin-top: 1; }

    /* Progress */
    ProgressBar { margin: 1 0; }
    """

    BINDINGS = [
        Binding("s", "do_start", "Start", show=True),
        Binding("x", "do_cancel", "Cancel", show=True),
        Binding("r", "do_reset", "Reset", show=True),
        Binding("escape", "go_back", "Back", show=True),
    ]

    def __init__(self, scan_type: str = "quick", reconnect_state: dict | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.scan_type = scan_type
        self._scanning = False
        self._done = False

        self._scanner: Any = None
        self._event_bus: Any = None
        self._cancel_token: Any = None
        self._fp_memory: Any = None
        self._quarantine: Any = None
        self._scan_history: Any = None
        self._event_queue: asyncio.Queue | None = None

        self._threats: list[dict] = []
        self._scan_start: float = 0
        self._run_id: int = 0
        self._recent_files: list[str] = []  # last N files scanned for display
        self._max_filelog: int = 50  # max files to show in log
        self._reconnect_state = reconnect_state

    # ── Layout ───────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        label = "QUICK SCAN" if self.scan_type == "quick" else "FULL SCAN"

        yield Header(show_clock=True)

        with Horizontal(id="panels"):
            # ── Left panel: status + controls ────────────────────────
            with Vertical(classes="left"):
                yield Static(f"🛡  CyberPet — {label}", classes="panel-title")
                yield Static("Initializing...", id="status")
                yield Static("Files:   0", id="files")
                yield Static("Threats: 0", id="threats")
                yield Static("Speed:   —", id="speed")
                yield ProgressBar(total=100, show_eta=False, id="pbar")
                yield Button("▶  START SCAN", id="start-btn", variant="success")
                yield Button("■  STOP SCAN", id="cancel-btn", variant="error", disabled=True)
                yield Button("←  BACK", id="back-btn", variant="default")

            # ── Right panel: files log (top) + threats (bottom) ──────
            with Vertical(classes="right"):
                with Vertical(id="filelog-section"):
                    yield Static("FILES BEING SCANNED", id="filelog-title")
                    yield Static("", id="filelog")

                with Vertical(id="threat-section"):
                    yield Static("THREATS DETECTED (0)", id="theader")
                    yield ListView(id="threat-list")

        yield Static("", id="prev")
        yield Footer()

    # ── Init ─────────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        # ── Reconnect to a running scan ─────────────────────────────
        if self._reconnect_state:
            state = self._reconnect_state
            self._reconnect_state = None

            self._event_bus = state["event_bus"]
            self._event_queue = state["event_queue"]
            self._scanner = state["scanner"]
            self._cancel_token = state["cancel_token"]
            self._threats = state.get("threats", [])
            self._scan_start = state.get("scan_start", time.time())
            self._run_id = state.get("run_id", 0)
            self._recent_files = state.get("recent_files", [])
            self._scanning = True
            self._done = False

            try:
                from cyberpet.false_positive_memory import FalsePositiveMemory
                self._fp_memory = FalsePositiveMemory()
            except Exception:
                pass
            try:
                from cyberpet.quarantine import QuarantineVault
                self._quarantine = QuarantineVault(event_bus=self._event_bus)
            except Exception:
                pass
            try:
                from cyberpet.scan_history import ScanHistory
                self._scan_history = ScanHistory()
            except Exception:
                pass

            # Update UI with current state
            self.query_one("#status", Static).update("Scanning")
            self.query_one("#start-btn", Button).disabled = True
            self.query_one("#start-btn", Button).label = "⏳ Scanning..."
            self.query_one("#cancel-btn", Button).disabled = False
            self.query_one("#back-btn", Button).disabled = False
            self.query_one("#threats", Static).update(
                f"Threats: {len(self._threats)}"
            )
            self.query_one("#theader", Static).update(
                f"THREATS DETECTED ({len(self._threats)})"
            )

            # Restore threat list visuals
            threat_list = self.query_one("#threat-list", ListView)
            for t in self._threats:
                icon = _threat_icon(t.get("threat_score", 0))
                fp = _trunc(t.get("filepath", ""), 40)
                cat = t.get("threat_category", "unknown")
                score = t.get("threat_score", 0)
                label = f"{icon} {fp} │ {cat} │ {score}"
                threat_list.append(ListItem(Static(label)))

            # Restore file log
            if self._recent_files:
                display = "\n".join(
                    _trunc(f, 55) for f in reversed(self._recent_files)
                )
                self.query_one("#filelog", Static).update(display)

            # Start polling events again
            self.set_interval(0.15, self._poll_events, name="poll")
            self._show_prev()
            return

        # ── Fresh scan setup ────────────────────────────────────────
        from cyberpet.events import EventBus

        self._event_bus = EventBus()

        try:
            from cyberpet.config import Config
            config = Config.load()
        except Exception:
            config = None

        try:
            from cyberpet.scan_history import ScanHistory
            self._scan_history = ScanHistory()
        except Exception:
            pass

        try:
            from cyberpet.false_positive_memory import FalsePositiveMemory
            self._fp_memory = FalsePositiveMemory()
        except Exception:
            pass

        try:
            from cyberpet.quarantine import QuarantineVault
            self._quarantine = QuarantineVault(event_bus=self._event_bus)
        except Exception:
            pass

        hash_db = None
        yara_engine = None
        try:
            from cyberpet.hash_db import HashDatabase
            hash_db = HashDatabase()
        except Exception:
            pass
        if config:
            try:
                from cyberpet.yara_engine import YaraEngine
                yara_engine = YaraEngine(config)
            except Exception:
                pass

        try:
            from cyberpet.scanner import FileScanner
            self._scanner = FileScanner(
                config=config or Config.load(),
                event_bus=self._event_bus,
                hash_db=hash_db,
                yara_engine=yara_engine,
                fp_memory=self._fp_memory,
            )
            self.query_one("#status", Static).update(
                "READY — press S or click ▶ START SCAN"
            )
        except Exception as exc:
            self.query_one("#status", Static).update(f"ERROR: {exc}")
            return

        self._show_prev()

    def _show_prev(self) -> None:
        try:
            if self._scan_history:
                last = self._scan_history.get_last_scan()
                if last:
                    self.query_one("#prev", Static).update(
                        f"  Previous: {last['scan_type']} scan | "
                        f"{last['started_at'][:16]} | "
                        f"Files: {last['files_scanned']:,} | "
                        f"Threats: {last['threats_found']}"
                    )
                else:
                    self.query_one("#prev", Static).update("  No previous scans")
        except Exception:
            pass

    # ── Button routing ───────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "start-btn":
            self.action_do_start()
        elif btn == "cancel-btn":
            self.action_do_cancel()
        elif btn == "back-btn":
            self.action_go_back()

    # ── Actions ──────────────────────────────────────────────────────────

    def action_do_start(self) -> None:
        if self._scanning or self._scanner is None:
            return

        from cyberpet.scanner import CancellationToken

        self._scanning = True
        self._done = False
        self._threats.clear()
        self._recent_files.clear()
        self._scan_start = time.time()
        self._cancel_token = CancellationToken()

        # Subscribe to events
        self._event_queue = asyncio.Queue()
        self._event_bus._subscribers.append(self._event_queue)

        # UI feedback
        self.query_one("#status", Static).update("Scanning")
        self.query_one("#files", Static).update("Files:   collecting targets...")
        self.query_one("#threats", Static).update("Threats: 0")
        self.query_one("#speed", Static).update("Speed:   —")
        self.query_one("#pbar", ProgressBar).update(progress=0)
        self.query_one("#filelog", Static).update("  Collecting scan targets...")
        self.query_one("#theader", Static).update("THREATS DETECTED (0)")
        self.query_one("#threat-list", ListView).clear()

        # Button states — disable start, change label
        btn = self.query_one("#start-btn", Button)
        btn.disabled = True
        btn.label = "⏳ Scanning..."
        self.query_one("#cancel-btn", Button).disabled = False
        self.query_one("#back-btn", Button).disabled = False

        # Record in history
        self._run_id = 0
        if self._scan_history:
            try:
                self._run_id = self._scan_history.start_scan(self.scan_type)
            except Exception:
                pass

        # Launch scan + poll timer
        asyncio.create_task(self._run_scan())
        self.set_interval(0.15, self._poll_events, name="poll")

    def action_do_cancel(self) -> None:
        if not self._scanning:
            return
        if self._cancel_token:
            self._cancel_token.cancel()

        # INSTANT cancel — don’t wait for scanner to return
        self._scanning = False
        self._done = True
        self._stop_poll()
        self._unsub()

        # Push partial scan results to PetState so main TUI shows them
        try:
            state = self.app.pet_state  # type: ignore[attr-defined]
            elapsed = time.time() - self._scan_start
            state.last_scan_duration = elapsed
            state.last_scan_time = time.time()
            state.last_scan_type = f"{self.scan_type} (cancelled)"
            # files_scanned is already being tracked via SCAN_PROGRESS events
        except Exception:
            pass

        # Clear app-level scan state
        if hasattr(self.app, "_active_scan_state"):
            self.app._active_scan_state = None  # type: ignore[attr-defined]
        if hasattr(self.app, "_scan_start_time"):
            self.app._scan_start_time = 0.0  # type: ignore[attr-defined]

        # Reset this screen’s UI immediately
        self.query_one("#status", Static).update("Cancelled")
        btn = self.query_one("#start-btn", Button)
        btn.disabled = False
        btn.label = "▶  START SCAN"
        self.query_one("#cancel-btn", Button).disabled = True
        self.query_one("#back-btn", Button).disabled = False

    def action_do_reset(self) -> None:
        if self._scanning:
            return
        self._done = False
        self._threats.clear()
        self._recent_files.clear()
        self.query_one("#status", Static).update(
            "READY — press S or click ▶ START SCAN"
        )
        self.query_one("#files", Static).update("Files:   0")
        self.query_one("#threats", Static).update("Threats: 0")
        self.query_one("#speed", Static).update("Speed:   —")
        self.query_one("#pbar", ProgressBar).update(progress=0)
        self.query_one("#filelog", Static).update("")
        self.query_one("#theader", Static).update("THREATS DETECTED (0)")
        self.query_one("#threat-list", ListView).clear()
        btn = self.query_one("#start-btn", Button)
        btn.disabled = False
        btn.label = "▶  START SCAN"
        self.query_one("#cancel-btn", Button).disabled = True
        self.query_one("#back-btn", Button).disabled = False

    def action_go_back(self) -> None:
        if self._scanning:
            # Save all live scan state to app for reconnection
            self._stop_poll()
            self.app._active_scan_state = {  # type: ignore[attr-defined]
                "event_bus": self._event_bus,
                "event_queue": self._event_queue,
                "scanner": self._scanner,
                "cancel_token": self._cancel_token,
                "threats": list(self._threats),
                "scan_start": self._scan_start,
                "scan_type": self.scan_type,
                "run_id": self._run_id,
                "recent_files": list(self._recent_files),
            }
            # Set scan start time so main TUI can calculate speed
            if hasattr(self.app, "_scan_start_time"):
                self.app._scan_start_time = self._scan_start  # type: ignore[attr-defined]
            # Immediately activate scan status on main TUI
            try:
                from cyberpet.ui.pet import ScanStatsWidget
                sw = self.app.query_one("#scan-panel", ScanStatsWidget)
                sw.scan_active = True
            except Exception:
                pass
            # DON'T unsub — the queue must keep receiving events
            self.app.pop_screen()
            return
        # Scan is done or never started — clean up
        self._unsub()
        if hasattr(self.app, "_active_scan_state"):
            self.app._active_scan_state = None  # type: ignore[attr-defined]
        self.app.pop_screen()

    # ── Scan execution ───────────────────────────────────────────────────

    async def _run_scan(self) -> None:
        try:
            if self.scan_type == "quick":
                report = await self._scanner.quick_scan(
                    cancel_token=self._cancel_token
                )
            else:
                report = await self._scanner.full_scan(
                    cancel_token=self._cancel_token
                )
            await self._event_queue.put(("DONE", report))
        except Exception as exc:
            await self._event_queue.put(("ERROR", str(exc)))

    # ── Event polling ────────────────────────────────────────────────────

    def _poll_events(self) -> None:
        if not self._event_queue or self._done:
            return

        from cyberpet.events import EventType

        processed = 0
        max_per_tick = 200  # Prevent UI freeze from queue overflow

        while not self._event_queue.empty() and processed < max_per_tick:
            try:
                item = self._event_queue.get_nowait()
            except Exception:
                break
            processed += 1

            # Sentinel: scan finished
            if isinstance(item, tuple) and len(item) == 2:
                kind, payload = item
                if kind == "DONE":
                    self._on_complete(payload)
                    return
                elif kind == "ERROR":
                    self._on_error(payload)
                    return

            if not hasattr(item, "type"):
                continue

            if item.type == EventType.SCAN_STARTED:
                self.query_one("#files", Static).update(
                    "Files:   0 / discovering..."
                )

            elif item.type == EventType.SCAN_PROGRESS:
                d = item.data
                done = d.get("files_scanned", 0)
                total = d.get("total_estimate", 0)
                pct = d.get("percent", 0)
                current = d.get("current_file", "")
                elapsed = time.time() - self._scan_start
                speed = done / elapsed if elapsed > 0 else 0

                if pct < 100 and total > done:
                    self.query_one("#files", Static).update(
                        f"Files:   {done:,} / ~{total:,}"
                    )
                else:
                    self.query_one("#files", Static).update(
                        f"Files:   {done:,} / {total:,}"
                    )
                self.query_one("#speed", Static).update(
                    f"Speed:   ~{speed:.0f} files/sec"
                )

                self.query_one("#pbar", ProgressBar).update(progress=pct)

                # Add current file to log (throttle UI updates)
                if current:
                    self._recent_files.append(current)
                    if len(self._recent_files) > self._max_filelog:
                        self._recent_files = self._recent_files[-self._max_filelog:]
                    # Only update UI every 10 files to reduce DOM thrashing
                    if len(self._recent_files) % 10 == 0 or pct >= 99:
                        display = "\n".join(
                            _trunc(f, 55) for f in reversed(self._recent_files[-30:])
                        )
                        self.query_one("#filelog", Static).update(display)

            elif item.type == EventType.THREAT_FOUND:
                self._add_threat(item.data)

    # ── Threat display ───────────────────────────────────────────────────

    def _add_threat(self, d: dict) -> None:
        from cyberpet.scanner import ThreatRecord

        entry = {
            "filepath": d.get("filepath", ""),
            "score": d.get("threat_score", 0),
            "category": d.get("threat_category", "unknown"),
            "action": "pending",
            "record": ThreatRecord(
                filepath=d.get("filepath", ""),
                threat_score=d.get("threat_score", 0),
                threat_reason=d.get("threat_reason", ""),
                matched_rules=d.get("matched_rules", []),
                file_hash=d.get("file_hash", ""),
                threat_category=d.get("threat_category", "unknown"),
            ),
        }
        self._threats.append(entry)
        c = len(self._threats)

        self.query_one("#threats", Static).update(f"Threats: {c}")
        self.query_one("#theader", Static).update(f"THREATS DETECTED ({c})")

        score = entry["score"]
        icon = _threat_icon(score)
        path = _trunc(entry["filepath"])
        label = f"{icon} {path}\n   Score: {score} | {entry['category']}"

        if score >= 90:
            cls = "threat-critical"
        elif score >= 70:
            cls = "threat-high"
        else:
            cls = "threat-medium"

        self.query_one("#threat-list", ListView).append(
            ListItem(Static(label), id=f"threat-{c - 1}", classes=cls)
        )

        if self._scan_history and self._run_id:
            try:
                self._scan_history.add_threat(self._run_id, entry["record"])
            except Exception:
                pass

    # ── Completion ───────────────────────────────────────────────────────

    def _on_complete(self, report: Any) -> None:
        self._done = True
        self._scanning = False
        self._stop_poll()
        self._unsub()
        # Clear active scan state so 's' shows menu again
        if hasattr(self.app, "_active_scan_state"):
            self.app._active_scan_state = None  # type: ignore[attr-defined]
        if hasattr(self.app, "_scan_start_time"):
            self.app._scan_start_time = 0.0  # type: ignore[attr-defined]

        elapsed = time.time() - self._scan_start
        cancelled = bool(self._cancel_token and self._cancel_token.is_cancelled())
        count = len(self._threats)

        if cancelled:
            self.query_one("#status", Static).update("Cancelled")
            if self._scan_history and self._run_id:
                try:
                    self._scan_history.cancel_scan(self._run_id)
                except Exception:
                    pass
        else:
            if count > 0:
                self.query_one("#status", Static).update(
                    f"Complete — {count} threat{'s' if count != 1 else ''} found"
                )
            else:
                self.query_one("#status", Static).update(
                    "Complete — System clean ✓"
                )
            self.query_one("#pbar", ProgressBar).update(progress=100)

            if self._scan_history and self._run_id:
                try:
                    self._scan_history.complete_scan(
                        self._run_id,
                        files_scanned=getattr(report, "files_scanned", 0),
                        threats_found=len(getattr(report, "threats_found", [])),
                        duration_seconds=elapsed,
                    )
                except Exception:
                    pass

        # Update main pet UI state
        self._update_pet_state(report, cancelled)

        # Re-enable buttons — label goes back to START SCAN
        btn = self.query_one("#start-btn", Button)
        btn.disabled = False
        btn.label = "▶  START SCAN"
        self.query_one("#cancel-btn", Button).disabled = True
        self.query_one("#back-btn", Button).disabled = False
        self._show_prev()

        # Backfill threats the poller may have missed
        known = {t["filepath"] for t in self._threats}
        for t in getattr(report, "threats_found", []):
            if t.filepath not in known:
                self._add_threat({
                    "filepath": t.filepath,
                    "threat_score": t.threat_score,
                    "threat_reason": t.threat_reason,
                    "threat_category": t.threat_category,
                    "matched_rules": t.matched_rules,
                    "file_hash": t.file_hash,
                })

    def _update_pet_state(self, report: Any, cancelled: bool) -> None:
        """Push scan results into the main PetState so the pet dashboard updates."""
        try:
            state = self.app.pet_state  # type: ignore[attr-defined]
            elapsed = time.time() - self._scan_start
            state.last_scan_duration = elapsed
            if not cancelled:
                state.last_scan_time = time.time()
                state.last_scan_type = self.scan_type
                state.last_scan_files_scanned = getattr(report, "files_scanned", 0)
                state.last_scan_threats_found = len(getattr(report, "threats_found", []))
                state.threats_blocked += len(getattr(report, "threats_found", []))
            else:
                state.last_scan_time = time.time()
                state.last_scan_type = f"{self.scan_type} (cancelled)"
        except Exception:
            pass

    def _on_error(self, msg: str) -> None:
        self._done = True
        self._scanning = False
        self._stop_poll()
        self._unsub()
        # Clear active scan state
        if hasattr(self.app, "_active_scan_state"):
            self.app._active_scan_state = None  # type: ignore[attr-defined]
        if hasattr(self.app, "_scan_start_time"):
            self.app._scan_start_time = 0.0  # type: ignore[attr-defined]
        self.query_one("#status", Static).update(f"ERROR: {msg}")
        btn = self.query_one("#start-btn", Button)
        btn.disabled = False
        btn.label = "▶  START SCAN"
        self.query_one("#cancel-btn", Button).disabled = True
        self.query_one("#back-btn", Button).disabled = False

    # ── Cleanup ──────────────────────────────────────────────────────────

    def _stop_poll(self) -> None:
        try:
            for timer in self._timers:
                if timer.name == "poll":
                    timer.stop()
        except Exception:
            pass

    def _unsub(self) -> None:
        try:
            if self._event_queue and self._event_bus:
                if self._event_queue in self._event_bus._subscribers:
                    self._event_bus._subscribers.remove(self._event_queue)
        except Exception:
            pass

    # ── Threat click → action modal ──────────────────────────────────────

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if not item.id or not item.id.startswith("threat-"):
            return
        try:
            idx = int(item.id.replace("threat-", ""))
        except ValueError:
            return
        if idx >= len(self._threats):
            return

        entry = self._threats[idx]
        if entry.get("action") != "pending":
            return

        from cyberpet.ui.threat_action import ThreatActionModal
        self.app.push_screen(
            ThreatActionModal(entry["record"]),
            callback=lambda result, i=idx: self._handle_action(result, i),
        )

    def _handle_action(self, result: dict | None, idx: int) -> None:
        if not result:
            return
        action = result.get("action")
        record = result.get("threat")
        if not action or not record:
            return
        if action == "quarantine":
            asyncio.create_task(self._quarantine_file(record, idx))
        elif action == "safe":
            asyncio.create_task(self._mark_safe(record, idx))

    async def _quarantine_file(self, record: Any, idx: int) -> None:
        try:
            if self._quarantine:
                await self._quarantine.quarantine_file(record.filepath, record)
            if self._fp_memory:
                self._fp_memory.record_quarantine_confirmation(record)
            self._threats[idx]["action"] = "quarantined"
            if self._scan_history and self._run_id:
                self._scan_history.update_threat_action(
                    self._run_id, record.filepath, "quarantined"
                )
            self._update_threat_visual(idx, "QUARANTINED")
            self.notify("🔒 File quarantined", severity="information")
        except Exception as exc:
            self.notify(f"Quarantine failed: {exc}", severity="error")

    async def _mark_safe(self, record: Any, idx: int) -> None:
        try:
            if self._fp_memory:
                self._fp_memory.record_false_positive(record)
            self._threats[idx]["action"] = "safe"
            if self._scan_history and self._run_id:
                self._scan_history.update_threat_action(
                    self._run_id, record.filepath, "marked_safe"
                )
            self._update_threat_visual(idx, "SAFE ✓")
            self.notify("✅ Marked safe — CyberPet will remember", severity="information")
        except Exception as exc:
            self.notify(f"Error: {exc}", severity="error")

    def _update_threat_visual(self, idx: int, suffix: str) -> None:
        try:
            item = self.query_one(f"#threat-{idx}", ListItem)
            entry = self._threats[idx]
            path = _trunc(entry["filepath"])
            for child in item.children:
                if isinstance(child, Static):
                    child.update(
                        f"[{suffix}] {path}\n"
                        f"   Score: {entry['score']} | {entry['category']}"
                    )
            item.set_classes("threat-handled")
        except Exception:
            pass
