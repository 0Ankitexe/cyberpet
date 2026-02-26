"""CyberPet Terminal UI built with Textual.

Displays the ASCII pet, system stats, and a scrollable event log.
Connects to the EventBus for live updates.
"""

from __future__ import annotations

import asyncio
import random
import time
from datetime import datetime

import psutil  # type: ignore[import]
from rich.text import Text  # type: ignore[import]
from textual.app import App, ComposeResult  # type: ignore[import]
from textual.containers import Horizontal, Vertical, VerticalScroll  # type: ignore[import]
from textual.reactive import reactive  # type: ignore[import]
from textual.widgets import Footer, Header, ProgressBar, Static  # type: ignore[import]

from cyberpet.events import Event, EventBus, EventType  # type: ignore[import]
from cyberpet.state import PetState  # type: ignore[import]
from cyberpet.ui.ascii_art import MoodArt  # type: ignore[import]
from cyberpet.ui.scan_menu import ScanMenuModal  # type: ignore[import]
from cyberpet.ui.scan_screen import ScanScreen  # type: ignore[import]


# Speech bubble messages per mood
SPEECH_MESSAGES: dict[str, list[str]] = {
    "SLEEPING": ["*yawn*...", "zzzz...", "all quiet..."],
    "HAPPY": ["System looks clean!", "All good here~", "Nothing suspicious today."],
    "ALERT": ["Hold on...", "Something caught my eye...", "Let me check this..."],
    "SUSPICIOUS": ["That looks weird.", "I'm watching this.", "Not sure about that command..."],
    "AGGRESSIVE": ["BLOCKED! Nice try.", "Not on my watch!", "Threat neutralized!"],
    "HEALING": ["Fixing things up...", "Almost done healing..."],
    "CRITICAL": ["MULTIPLE THREATS!", "SYSTEM UNDER ATTACK!", "LOCKDOWN MODE!"],
}

# Severity-to-color mapping for event log
SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

MOOD_BORDER_COLORS = {
    "SLEEPING": "blue",
    "HAPPY": "green",
    "ALERT": "yellow",
    "SUSPICIOUS": "#ff8c00",
    "AGGRESSIVE": "red",
    "HEALING": "cyan",
    "CRITICAL": "bright_red",
}

MOOD_BACKGROUNDS = {
    "AGGRESSIVE": "#2a0000",
    "CRITICAL": "#3a0000",
}


def _severity_level(severity: int) -> str:
    """Map numeric severity to a named level."""
    if severity >= 80:
        return "critical"
    elif severity >= 60:
        return "high"
    elif severity >= 30:
        return "medium"
    return "low"


def _determine_mood(state: PetState) -> str:
    """Determine the pet's mood based on recent events.

    Priority: CRITICAL > AGGRESSIVE > ALERT > SUSPICIOUS > SLEEPING > HEALING > HAPPY

    Args:
        state: Current pet state with recent events.

    Returns:
        The mood string.
    """
    now = time.time()

    # Check recent events for mood determination
    hard_block_recent = False
    warn_recent = False
    threat_recent = False
    threat_found_recent = False
    file_access_block_recent = False
    quarantine_aggressive_recent = False
    quarantine_alert_recent = False
    critical_set = False

    for evt_time, evt_type, _evt_severity in state.recent_events:
        age = now - evt_time

        if evt_type == EventType.CMD_BLOCKED and age < 60:
            hard_block_recent = True

        if evt_type == EventType.CMD_WARNED and age < 30:
            warn_recent = True

        if evt_type == EventType.THREAT_DETECTED and age < 120:
            threat_recent = True

        if evt_type == EventType.THREAT_FOUND and age < 120:
            threat_found_recent = True

        if evt_type == EventType.FILE_ACCESS_BLOCKED and age < 120:
            file_access_block_recent = True

        if evt_type == EventType.QUARANTINE_SUCCESS:
            if age < 8:
                quarantine_aggressive_recent = True
            elif age < 120:
                quarantine_alert_recent = True

        if evt_type == EventType.MOOD_CHANGE and age < 120:
            # Check if CRITICAL was explicitly set
            critical_set = True

    if critical_set and state.current_mood == "CRITICAL":
        return "CRITICAL"
    if quarantine_aggressive_recent:
        return "AGGRESSIVE"
    if hard_block_recent:
        return "AGGRESSIVE"
    if file_access_block_recent or quarantine_alert_recent:
        return "ALERT"
    if warn_recent:
        return "ALERT"
    if threat_found_recent:
        return "SUSPICIOUS"
    if threat_recent:
        return "SUSPICIOUS"

    hour = datetime.now().hour
    if 0 <= hour < 6 and not state.recent_events:
        return "SLEEPING"

    return "HAPPY"


class PetFaceWidget(Static):
    """Widget displaying the ASCII pet face and speech bubble."""

    mood = reactive("HAPPY")
    speech = reactive("System looks clean!")
    pet_name = reactive("Byte")

    def render(self) -> str:
        """Render the pet face, name, mood, and speech bubble."""
        art = MoodArt()
        face = art.get_face(self.mood)
        return (
            f"{face}\n\n"
            f"  {self.pet_name}\n"
            f"  Mood: {self.mood}\n\n"
            f'  💬 "{self.speech}"'
        )


class SystemStatsWidget(Static):
    """Widget displaying live system statistics."""

    cpu = reactive(0.0)
    ram = reactive(0.0)
    uptime = reactive(0)
    threats = reactive(0)
    intercepted = reactive(0)

    def render(self) -> str:
        """Render the system stats panel.

        All lines are exactly 24 characters wide (22 inner + 2 border):
          border  inner (22 chars)  border
            │   CPU  [██████]  87.3%   │
        """
        uptime_str = self._format_uptime(self.uptime)
        cpu_bar = self._bar(self.cpu)   # 6 chars wide
        ram_bar = self._bar(self.ram)

        # Exact widths (inner = 22, total = 24):
        #  " CPU  [" (7) + bar(6) + "] " (2) + cpu:5.1f (5) + "% " (2) = 22
        #  " Uptime: " (9) + uptime:>12s (12) + " " (1)               = 22
        #  " Blocked:" (9) + threats:>12d (12) + " " (1)              = 22
        #  " Checked:" (9) + intercepted:>12d (12) + " " (1)          = 22
        return (
            "╭──────────────────────╮\n"
            "│      System Stats    │\n"
            "├──────────────────────┤\n"
            f"│ CPU  [{cpu_bar}] {self.cpu:5.1f}% │\n"
            f"│ RAM  [{ram_bar}] {self.ram:5.1f}% │\n"
            "├──────────────────────┤\n"
            f"│ Uptime: {uptime_str:>12s} │\n"
            f"│ Blocked:{self.threats:>12d} │\n"
            f"│ Checked:{self.intercepted:>12d} │\n"
            "╰──────────────────────╯"
        )

    @staticmethod
    def _bar(percent: float, width: int = 6) -> str:
        """Create a simple progress bar (6 chars wide by default)."""
        filled = int(percent / 100 * width)
        return "█" * filled + "░" * (width - filled)

    @staticmethod
    def _format_uptime(seconds: int) -> str:
        """Format uptime as human-readable string."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        else:
            h = seconds // 3600
            m = (seconds % 3600) // 60
            return f"{h}h {m}m"


class EventLogWidget(VerticalScroll):
    """Scrollable event log showing the most recent 20 events."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._events: list[tuple[str, str, int]] = []

    def add_event(self, text: str, severity: int = 0) -> None:
        """Add an event to the log.

        Args:
            text: Event text to display.
            severity: Numeric severity (0-100) for color coding.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._events.append((timestamp, text, severity))

        # Keep only last 20 entries.
        if len(self._events) > 20:
            self._events = self._events[-20:]  # type: ignore[index]

        self._refresh_log()

    def _refresh_log(self) -> None:
        """Refresh the displayed log entries."""
        self.remove_children()
        for timestamp, text, severity in self._events:
            level = _severity_level(severity)
            color = SEVERITY_COLORS.get(level, "white")
            entry = Text(
                f"{timestamp} │ {text}",
                style=color,
                no_wrap=True,
                overflow="ellipsis",
            )
            self.mount(Static(entry))
        self.scroll_end(animate=False)


class ScanStatsWidget(Static):
    """Widget displaying live scan progress or last scan results."""

    last_scan = reactive("never")
    files_scanned = reactive(0)
    threats_found = reactive(0)
    quarantined = reactive(0)
    last_threat = reactive("none")
    scan_active = reactive(False)
    scan_percent = reactive(0)
    scan_speed = reactive(0.0)
    scan_duration = reactive(0.0)

    def render(self) -> str:
        """Render scan status."""
        threat = self.last_threat or "none"
        if len(threat) > 20:
            threat = threat[:17] + "..."

        if self.scan_active:
            pct = self.scan_percent
            bar_w = 20
            filled = int(pct / 100 * bar_w)
            bar = "\u2588" * filled + "\u2591" * (bar_w - filled)
            return (
                "\u2501\u2501 Scan Status \u2501\u2501\n"
                f"  SCANNING...\n"
                f"  [{bar}] {pct:>3d}%\n"
                f"  Files: {self.files_scanned:>6,d}  Speed: ~{self.scan_speed:.0f}/s\n"
                f"  Threats: {self.threats_found}  Quarantined: {self.quarantined}"
            )
        else:
            dur = self.scan_duration
            if dur > 0:
                mins, secs = divmod(int(dur), 60)
                dur_str = f"{mins}m {secs}s" if mins else f"{secs}s"
            else:
                dur_str = "\u2014"
            return (
                "\u2501\u2501 Scan Status \u2501\u2501\n"
                f"  Last scan: {self.last_scan}\n"
                f"  Files: {self.files_scanned:,d}  Duration: {dur_str}\n"
                f"  Threats: {self.threats_found}  Quarantined: {self.quarantined}"
            )


class ScanFileLogWidget(VerticalScroll):
    """Scrollable real-time log of files being scanned."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._files: list[str] = []
        self._max_files: int = 40
        self._dirty = False

    def add_file(self, filepath: str) -> None:
        """Add a scanned file to the log."""
        if len(filepath) > 55:
            filepath = filepath[:25] + "..." + filepath[-24:]
        self._files.append(filepath)
        if len(self._files) > self._max_files:
            self._files = self._files[-self._max_files:]
        self._dirty = True

    def clear_log(self) -> None:
        """Clear the file log."""
        self._files.clear()
        self._dirty = True
        self._do_refresh()

    def on_mount(self) -> None:
        self.set_interval(0.5, self._maybe_refresh)

    def _maybe_refresh(self) -> None:
        if self._dirty:
            self._dirty = False
            self._do_refresh()

    def _do_refresh(self) -> None:
        """Refresh the displayed file entries."""
        self.remove_children()
        for f in reversed(self._files[-20:]):
            entry = Text(f, style="dim", no_wrap=True, overflow="ellipsis")
            self.mount(Static(entry))
        self.scroll_end(animate=False)

class CyberPetApp(App):
    """CyberPet Terminal User Interface.

    Layout:
    - Top row: Pet face (left 30%) + System stats (right 70%)
    - Bottom row: Event log (left 50%) + Scan section (right 50%)
    - Scan section: Scan status (top) + File log (bottom)

    Connects to the EventBus for live updates.
    """

    CSS = """
    Screen {
        layout: vertical;
    }

    #top-row {
        height: 35%;
        layout: horizontal;
    }

    #pet-panel {
        width: 25%;
        height: 100%;
        border: round green;
        padding: 1;
    }

    #stats-panel {
        width: 75%;
        height: 100%;
        border: round cyan;
        padding: 1;
    }

    #bottom-row {
        height: 65%;
        layout: horizontal;
    }

    #event-log {
        width: 50%;
        height: 100%;
        border: round yellow;
        padding: 0 1;
    }

    #scan-section {
        width: 50%;
        height: 100%;
        layout: vertical;
    }

    #scan-panel {
        height: 45%;
        border: round magenta;
        padding: 0 1;
    }

    #scan-filelog {
        height: 55%;
        border: round #444444;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "toggle_dark", "Toggle Dark"),
        ("s", "open_scan_menu", "Scan"),
    ]
    _MOOD_EVENT_TYPES = {
        EventType.CMD_BLOCKED,
        EventType.CMD_WARNED,
        EventType.THREAT_DETECTED,
        EventType.THREAT_FOUND,
        EventType.QUARANTINE_SUCCESS,
        EventType.FILE_ACCESS_BLOCKED,
        EventType.MOOD_CHANGE,
    }

    def __init__(
        self,
        event_bus: EventBus | None = None,
        pet_state: PetState | None = None,
        pet_name: str = "Byte",
        event_stream_socket: str = "/var/run/cyberpet_events.sock",
        show_allowed_events: bool = False,
        **kwargs,
    ) -> None:
        """Initialize the TUI."""
        super().__init__(**kwargs)
        self.event_bus = event_bus
        self.pet_state = pet_state or PetState()
        self._pet_name = pet_name
        self._event_stream_socket = event_stream_socket
        self._show_allowed_events = show_allowed_events
        self._stream_connected = False
        self._event_listener_task: asyncio.Task | None = None
        self._last_outcome_cmd = ""
        self._last_outcome_at = 0.0
        self._active_scan_state: dict | None = None
        self._scan_start_time: float = 0.0

    def compose(self) -> ComposeResult:  # type: ignore[override]
        """Build the UI layout."""
        yield Header(show_clock=True)
        with Horizontal(id="top-row"):  # type: ignore[call-arg]
            yield PetFaceWidget(id="pet-panel")  # type: ignore[call-arg]
            yield SystemStatsWidget(id="stats-panel")  # type: ignore[call-arg]
        with Horizontal(id="bottom-row"):  # type: ignore[call-arg]
            yield EventLogWidget(id="event-log")  # type: ignore[call-arg]
            with Vertical(id="scan-section"):  # type: ignore[call-arg]
                yield ScanStatsWidget(id="scan-panel")  # type: ignore[call-arg]
                yield ScanFileLogWidget(id="scan-filelog")  # type: ignore[call-arg]
        yield Footer()

    def on_mount(self) -> None:
        """Start background tasks when the app mounts."""
        self.set_interval(2.0, self._update_stats)
        self.set_interval(10.0, self._update_speech)
        self.set_interval(2.0, self._update_mood)

        # Poll the active scan's event queue for live progress on main TUI
        self.set_interval(0.3, self._poll_active_scan)

        self._event_listener_task = asyncio.create_task(self._event_listener())

        pet_widget = self.query_one("#pet-panel", PetFaceWidget)
        pet_widget.pet_name = self._pet_name
        self._apply_mood_theme(self.pet_state.current_mood)
        self._refresh_scan_widget()

    async def _event_listener(self) -> None:
        """Listen for events and update the UI.

        If an in-process EventBus is provided (daemon+TUI in one process),
        subscribe directly.  Otherwise connect to the daemon's event stream
        unix socket (configured via config.toml) which broadcasts every
        event as a JSON line — this is the normal case for `cyberpet pet`.
        """
        if self.event_bus:
            # In-process mode: subscribe directly to the shared EventBus
            async for event in self.event_bus.subscribe():
                self._handle_event(event)
        else:
            # Cross-process mode: read JSON events from the daemon's stream socket
            await self._remote_event_listener()

    async def _remote_event_listener(self) -> None:
        """Connect to the daemon's event stream socket and process events.

        Retries the connection every 2 seconds if the daemon is not yet
        running or the socket doesn't exist yet.
        """
        import json  # type: ignore[import]

        stream_socket = self._event_stream_socket

        while True:
            try:
                reader, writer = await asyncio.open_unix_connection(stream_socket)
                self._stream_connected = True
                # Show a connected indicator in the log
                try:
                    log_widget = self.query_one("#event-log", EventLogWidget)
                    log_widget.add_event("Connected to daemon event stream", severity=0)
                except Exception:
                    pass

                async for raw_line in reader:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                        event = self._event_from_payload(payload)
                        if event is None:
                            continue
                        self._handle_event(event)
                    except Exception:
                        # Malformed line or event handling error — skip this line only.
                        continue

                writer.close()
                self._stream_connected = False
                try:
                    log_widget = self.query_one("#event-log", EventLogWidget)
                    log_widget.add_event("Daemon disconnected; reconnecting", severity=20)
                except Exception:
                    pass

            except PermissionError:
                # Socket exists but we don't have permission (group not active yet).
                self._stream_connected = False
                try:
                    log_widget = self.query_one("#event-log", EventLogWidget)
                    log_widget.add_event(
                        "⚠ Event stream: permission denied. Run 'exec newgrp cyberpet' or open a fresh terminal.",
                        severity=40,
                    )
                except Exception:
                    pass
                await asyncio.sleep(5)
                continue
            except (ConnectionRefusedError, FileNotFoundError, OSError):
                # Daemon not running yet — wait and retry silently
                self._stream_connected = False
                await asyncio.sleep(2)
                continue
            except asyncio.CancelledError:
                break
            except Exception:
                self._stream_connected = False
                await asyncio.sleep(2)
                continue

    @staticmethod
    def _event_from_payload(payload: dict) -> Event | None:
        """Build an Event from stream payload, skipping malformed entries."""
        event_type_raw = payload.get("type")
        if not isinstance(event_type_raw, str):
            return None
        try:
            event_type = EventType(event_type_raw)
        except ValueError:
            return None
        data = payload.get("data", {})
        if not isinstance(data, dict):
            data = {}
        severity_raw = payload.get("severity", 0)
        try:
            severity = int(severity_raw)
        except (TypeError, ValueError):
            severity = 0
        source = payload.get("source", "daemon")
        if not isinstance(source, str):
            source = "daemon"
        return Event(
            type=event_type,
            source=source,
            data=data,
            severity=severity,
        )

    @staticmethod
    def _clip_text(value: object) -> str:
        """Normalize text to a single line for compact activity entries."""
        return " ".join(str(value).split())

    @staticmethod
    def _risk_label(severity: int) -> str:
        """Return a user-friendly risk label from numeric severity."""
        level = _severity_level(severity)
        if level == "critical":
            return "Critical"
        if level == "high":
            return "High"
        if level == "medium":
            return "Medium"
        return "Low"

    def _command_preview(self, command: str, max_len: int = 38) -> str:
        """Build a short command preview for activity feed lines."""
        cmd = self._clip_text(command)
        if not cmd:
            return "unknown command"
        if len(cmd) <= max_len:
            return cmd
        return cmd[: max_len - 3] + "..."

    def _friendly_reason(self, reason: str) -> str:
        """Convert technical scorer reasons into user-friendly explanations."""
        normalized = self._clip_text(reason)
        if not normalized:
            return "potentially unsafe behavior detected"

        core = normalized.split(";", 1)[0].strip().lower()
        reason_map = {
            "piping remote content directly to shell": "downloads and runs a script directly from the internet",
            "piping remote download directly to shell": "downloads and runs a script directly from the internet",
            "piping wget output directly to shell": "downloads and runs a script directly from the internet",
            "escalating to root shell": "opens a root shell with elevated privileges",
            "setting ld_preload (library injection)": "injects a custom library into commands (LD_PRELOAD)",
            "recursive delete of root filesystem": "attempts a destructive system-wide delete",
            "format disk device": "attempts to format a disk device",
            "overwrite disk device with zeros/random data": "attempts to overwrite a disk device",
            "reverse shell via netcat": "looks like a reverse shell command",
            "reverse shell via /dev/tcp": "looks like a reverse shell command",
            "encoded python payload execution": "runs an encoded script payload",
        }
        return reason_map.get(core, core.capitalize())

    def _format_event_log_line(self, event: Event, command: str, reason: str) -> str | None:
        """Return user-facing activity line for significant events only."""
        cmd = self._command_preview(command)
        why = self._friendly_reason(reason)
        sev = event.severity
        risk = self._risk_label(sev)

        if event.type == EventType.CMD_BLOCKED:
            return f"BLOCKED: {cmd} | {why} | Risk: {risk} ({sev})"
        if event.type == EventType.CMD_WARNED:
            return f"WARNING: {cmd} | {why} | Risk: {risk} ({sev})"
        if event.type == EventType.CMD_ALLOWED:
            if not self._show_allowed_events:
                return None
            return f"ALLOWED: {cmd}"
        if event.type == EventType.THREAT_DETECTED:
            return f"THREAT: {why} | Risk: {risk} ({sev})"
        if event.type == EventType.THREAT_FOUND:
            filepath = self._command_preview(event.data.get("filepath", ""), max_len=30)
            category = self._clip_text(event.data.get("threat_category", "unknown"))
            return f"THREAT FILE: {filepath} | {category} | Risk: {risk} ({sev})"
        if event.type == EventType.QUARANTINE_SUCCESS:
            filepath = self._command_preview(event.data.get("original_path", ""), max_len=28)
            category = self._clip_text(event.data.get("threat_category", "unknown"))
            return f"QUARANTINED: {filepath} | {category}"
        if event.type == EventType.FILE_ACCESS_BLOCKED:
            proc = self._clip_text(event.data.get("process_name", "process"))
            target = self._command_preview(event.data.get("target_path", ""), max_len=24)
            return f"ACCESS BLOCKED: {proc} -> {target}"
        if event.type == EventType.FILE_ACCESS_SUSPICIOUS:
            proc = self._clip_text(event.data.get("process_name", "process"))
            target = self._command_preview(event.data.get("target_path", ""), max_len=24)
            return f"ACCESS WATCH: {proc} -> {target}"
        # Skip noisy/internal events from activity feed (e.g. SYSTEM_STAT_UPDATE).
        return None

    def _handle_event(self, event: Event) -> None:
        """Process an incoming event and update the UI.

        Args:
            event: The event to process.
        """
        state = self.pet_state

        # Update counters
        if event.type == EventType.CMD_INTERCEPTED:
            state.commands_intercepted += 1
        elif event.type == EventType.CMD_BLOCKED:
            state.commands_blocked += 1
            state.threats_blocked += 1
        elif event.type == EventType.QUARANTINE_SUCCESS:
            state.files_quarantined += 1

        if event.type in self._MOOD_EVENT_TYPES:
            # Track recent mood-relevant events only.
            state.recent_events.append((time.time(), event.type, event.severity))
            cutoff = time.time() - 120
            state.recent_events = [
                (t, typ, sev) for t, typ, sev in state.recent_events if t > cutoff
            ]

        # Update last event message
        cmd = event.data.get("command", "")
        reason = event.data.get("reason", "")

        if event.type in (EventType.CMD_BLOCKED, EventType.CMD_WARNED, EventType.CMD_ALLOWED):
            self._last_outcome_cmd = self._clip_text(cmd)
            self._last_outcome_at = time.time()

        if event.type == EventType.CMD_BLOCKED:
            state.last_event_message = f"BLOCKED: {cmd[:40]}"
            pet_widget = self.query_one("#pet-panel", PetFaceWidget)
            pet_widget.speech = f"Blocked: {cmd[:50]}"
        elif event.type == EventType.CMD_WARNED:
            state.last_event_message = f"WARNED: {cmd[:40]}"
            pet_widget = self.query_one("#pet-panel", PetFaceWidget)
            pet_widget.speech = f"Warning: {cmd[:50]}"
        elif event.type == EventType.THREAT_DETECTED:
            state.last_event_message = f"THREAT: {reason[:40]}"
        elif event.type == EventType.THREAT_FOUND:
            threat_category = self._clip_text(event.data.get("threat_category", "unknown"))
            filepath = self._clip_text(event.data.get("filepath", ""))
            state.last_threat_name = f"{threat_category}: {filepath}" if filepath else threat_category
            state.last_event_message = f"THREAT FILE: {threat_category}"
        elif event.type == EventType.QUARANTINE_SUCCESS:
            category = self._clip_text(event.data.get("threat_category", "unknown"))
            path = self._clip_text(event.data.get("original_path", ""))
            state.last_threat_name = f"{category}: {path}" if path else category
            state.last_event_message = f"QUARANTINED: {category}"
        elif event.type == EventType.FILE_ACCESS_BLOCKED:
            proc = self._clip_text(event.data.get("process_name", "process"))
            target = self._clip_text(event.data.get("target_path", ""))
            state.last_event_message = f"ACCESS BLOCKED: {proc} -> {target[:30]}"
        elif event.type == EventType.SCAN_COMPLETE:
            state.last_scan_time = time.time()
            state.last_scan_type = self._clip_text(event.data.get("scan_type", "scan"))
            try:
                state.last_scan_files_scanned = int(event.data.get("files_scanned", 0))
            except (TypeError, ValueError):
                state.last_scan_files_scanned = 0
            try:
                state.last_scan_threats_found = int(event.data.get("threats_found_count", 0))
            except (TypeError, ValueError):
                state.last_scan_threats_found = 0
            state.last_event_message = (
                f"SCAN {state.last_scan_type.upper()}: "
                f"{state.last_scan_files_scanned} files, "
                f"{state.last_scan_threats_found} threats"
            )
            # Clear active scan state on main TUI
            self._scan_start_time = 0.0
            try:
                scan_widget = self.query_one("#scan-panel", ScanStatsWidget)
                scan_widget.scan_active = False
            except Exception:
                pass
        elif event.type == EventType.SYSTEM_STAT_UPDATE:
            state.cpu_percent = event.data.get("cpu", 0.0)
            state.ram_percent = event.data.get("ram", 0.0)
        elif event.type == EventType.SCAN_PROGRESS:
            # Live scan progress — update scan widgets immediately
            d = event.data
            state.last_scan_files_scanned = d.get("files_scanned", 0)
            state.last_scan_threats_found = d.get("threats_found_count", state.last_scan_threats_found)

            try:
                scan_widget = self.query_one("#scan-panel", ScanStatsWidget)
                scan_widget.scan_active = True
                scan_widget.scan_percent = d.get("percent", 0)
                scan_widget.files_scanned = d.get("files_scanned", 0)
                scan_widget.threats_found = state.last_scan_threats_found
                elapsed = time.time() - self._scan_start_time if self._scan_start_time else 1.0
                speed = d.get("files_scanned", 0) / max(elapsed, 0.1)
                scan_widget.scan_speed = speed
            except Exception:
                pass

            # Add current file to the file log
            current_file = d.get("current_file", "")
            if current_file:
                try:
                    filelog = self.query_one("#scan-filelog", ScanFileLogWidget)
                    filelog.add_file(current_file)
                except Exception:
                    pass

        # Add to event log
        try:
            log_widget = self.query_one("#event-log", EventLogWidget)
            skip_event_log = False
            if event.type == EventType.THREAT_DETECTED:
                threat_cmd = self._clip_text(event.data.get("command", ""))
                if (
                    threat_cmd
                    and threat_cmd == self._last_outcome_cmd
                    and (time.time() - self._last_outcome_at) < 5
                ):
                    # Hard-block path emits THREAT_DETECTED right after CMD_BLOCKED.
                    # Keep activity concise by suppressing duplicate threat line.
                    skip_event_log = True

            event_text = None if skip_event_log else self._format_event_log_line(event, cmd, reason)
            if event_text:
                log_widget.add_event(event_text, event.severity)
        except Exception:
            pass

        # Refresh counter panel immediately so blocked/checked moves without waiting.
        self._refresh_stats_widget()
        self._refresh_scan_widget()
        self._update_mood()

    def _poll_active_scan(self) -> None:
        """Poll the background scan's event queue for live progress."""
        state_dict = self._active_scan_state
        if state_dict is None:
            return

        queue = state_dict.get("event_queue")
        if queue is None:
            return

        from cyberpet.events import EventType

        processed = 0
        max_per_tick = 100  # Prevent UI freeze from queue overflow

        while not queue.empty() and processed < max_per_tick:
            try:
                item = queue.get_nowait()
            except Exception:
                break
            processed += 1

            # Check for scan completion sentinel
            if isinstance(item, tuple) and len(item) == 2:
                kind, payload = item
                if kind in ("DONE", "ERROR"):
                    # Scan finished while user was on main TUI
                    self._active_scan_state = None
                    self._scan_start_time = 0.0

                    try:
                        scan_widget = self.query_one("#scan-panel", ScanStatsWidget)
                        scan_widget.scan_active = False
                    except Exception:
                        pass

                    # Show notification
                    if kind == "DONE":
                        files = getattr(payload, "files_scanned", 0) if payload else 0
                        threats = getattr(payload, "threats_found", 0) if payload else 0
                        self.notify(
                            f"Scan complete — {files:,d} files, {threats} threats",
                            severity="information" if threats == 0 else "warning",
                        )
                    else:
                        self.notify(f"Scan error: {payload}", severity="error")

                    self._refresh_scan_widget()
                    return
                continue

            if not hasattr(item, "type"):
                continue

            if item.type == EventType.SCAN_PROGRESS:
                d = item.data
                state = self.pet_state
                state.last_scan_files_scanned = d.get("files_scanned", 0)
                state.last_scan_threats_found = d.get(
                    "threats_found_count", state.last_scan_threats_found
                )

                try:
                    scan_widget = self.query_one("#scan-panel", ScanStatsWidget)
                    scan_widget.scan_active = True
                    scan_widget.scan_percent = d.get("percent", 0)
                    scan_widget.files_scanned = d.get("files_scanned", 0)
                    scan_widget.threats_found = state.last_scan_threats_found
                    elapsed = (
                        time.time() - self._scan_start_time
                        if self._scan_start_time
                        else 1.0
                    )
                    speed = d.get("files_scanned", 0) / max(elapsed, 0.1)
                    scan_widget.scan_speed = speed
                except Exception:
                    pass

                current_file = d.get("current_file", "")
                if current_file:
                    try:
                        filelog = self.query_one("#scan-filelog", ScanFileLogWidget)
                        filelog.add_file(current_file)
                    except Exception:
                        pass

            elif item.type == EventType.THREAT_FOUND:
                self.notify(
                    f"\u26a0 Threat: {item.data.get('filepath', 'unknown')[:40]}",
                    severity="warning",
                )

    def _update_stats(self) -> None:
        """Update system stats from psutil."""
        state = self.pet_state
        state.cpu_percent = psutil.cpu_percent(interval=None)
        state.ram_percent = psutil.virtual_memory().percent

        self._refresh_stats_widget()

        # Increment uptime
        state.uptime_seconds += 2

    def _refresh_stats_widget(self) -> None:
        """Push latest state values into stats widget."""
        state = self.pet_state
        try:
            stats_widget = self.query_one("#stats-panel", SystemStatsWidget)
            stats_widget.cpu = state.cpu_percent
            stats_widget.ram = state.ram_percent
            stats_widget.uptime = state.uptime_seconds
            stats_widget.threats = state.threats_blocked
            stats_widget.intercepted = state.commands_intercepted
        except Exception:
            pass

    def _refresh_scan_widget(self) -> None:
        """Push latest scan/quarantine values into scan widget."""
        state = self.pet_state
        try:
            scan_widget = self.query_one("#scan-panel", ScanStatsWidget)

            # Check if scan is currently running
            is_scanning = self._active_scan_state is not None
            scan_widget.scan_active = is_scanning

            if not is_scanning:
                if state.last_scan_time > 0:
                    stamp = datetime.fromtimestamp(state.last_scan_time).strftime("%H:%M:%S")
                    scan_name = state.last_scan_type or "scan"
                    scan_widget.last_scan = f"{scan_name} {stamp}"
                else:
                    scan_widget.last_scan = "never"

            scan_widget.files_scanned = state.last_scan_files_scanned
            scan_widget.threats_found = state.last_scan_threats_found
            scan_widget.quarantined = state.files_quarantined
            scan_widget.last_threat = state.last_threat_name or "none"
            scan_widget.scan_duration = state.last_scan_duration
        except Exception:
            pass

    def _update_mood(self) -> None:
        """Recalculate and update the pet's mood."""
        new_mood = _determine_mood(self.pet_state)
        self.pet_state.current_mood = new_mood

        pet_widget = self.query_one("#pet-panel", PetFaceWidget)
        pet_widget.mood = new_mood
        self._apply_mood_theme(new_mood)

    def _update_speech(self) -> None:
        """Pick a random speech bubble message for the current mood."""
        mood = self.pet_state.current_mood
        messages = SPEECH_MESSAGES.get(mood, SPEECH_MESSAGES["HAPPY"])
        speech = random.choice(messages)

        pet_widget = self.query_one("#pet-panel", PetFaceWidget)
        pet_widget.speech = speech

    def action_toggle_dark(self) -> None:
        """Toggle dark mode."""
        self.theme = "textual-light" if self.theme == "textual-dark" else "textual-dark"

    def action_open_scan_menu(self) -> None:
        """Open the scan type selection modal, or return to active scan."""
        # If a scan is running in the background, create a NEW screen
        # that reconnects to the running scan state
        if self._active_scan_state is not None:
            try:
                screen = ScanScreen(
                    scan_type=self._active_scan_state.get("scan_type", "quick"),
                    reconnect_state=self._active_scan_state,
                )
                self._active_scan_state = None  # consumed by the new screen
                self.push_screen(screen)
                return
            except Exception:
                self._active_scan_state = None
        try:
            self.push_screen(ScanMenuModal(), callback=self._on_scan_menu_result)
        except Exception as exc:
            self.notify(f"Scan menu error: {exc}", severity="error")

    def _on_scan_menu_result(self, result: str | None) -> None:
        """Handle scan menu selection."""
        if result in ("quick", "full"):
            try:
                self._scan_start_time = time.time()
                # Clear file log for new scan
                try:
                    self.query_one("#scan-filelog", ScanFileLogWidget).clear_log()
                except Exception:
                    pass
                screen = ScanScreen(scan_type=result)
                self.push_screen(screen)
            except Exception as exc:
                self.notify(f"Scan screen error: {exc}", severity="error")

    async def on_unmount(self) -> None:
        """Clean up background listener task when the app exits."""
        if self._event_listener_task is not None:
            self._event_listener_task.cancel()
            await asyncio.gather(self._event_listener_task, return_exceptions=True)
            self._event_listener_task = None

    def _apply_mood_theme(self, mood: str) -> None:
        """Adjust panel visuals based on current mood."""
        pet_widget = self.query_one("#pet-panel", PetFaceWidget)
        border_color = MOOD_BORDER_COLORS.get(mood, "green")
        pet_widget.styles.border = ("round", border_color)
        pet_widget.styles.background = MOOD_BACKGROUNDS.get(mood, "transparent")
