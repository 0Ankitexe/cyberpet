"""Shared state for CyberPet.

Contains the PetState dataclass used by both the daemon and the TUI.
Kept in a separate module to avoid circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Valid mood values in priority order (highest wins)
MOODS = ("CRITICAL", "AGGRESSIVE", "ALERT", "SUSPICIOUS", "SLEEPING", "HEALING", "HAPPY")

DEFAULT_MOOD = "HAPPY"


@dataclass
class PetState:
    """Mutable runtime state shared by daemon and TUI.

    Attributes:
        cpu_percent: Latest CPU utilization.
        ram_percent: Latest RAM utilization.
        uptime_seconds: Daemon uptime in seconds.
        commands_intercepted: Total commands checked.
        commands_blocked: Total commands blocked.
        threats_blocked: Total threats mitigated.
        current_mood: Current pet mood string.
        recent_events: Recent mood-relevant events (time, type, severity).
        last_event_message: Last notable event message string.
        last_scan_time: Timestamp of the last completed scan (0.0 if never).
        last_scan_type: Last scan type label ("quick"/"full"/"scan").
        last_scan_files_scanned: Number of files scanned in last scan.
        last_scan_threats_found: Number of threats found in last scan.
        files_quarantined: Total files currently in quarantine.
        last_threat_name: Name/category of the most recent threat found.
        scan_in_progress: Whether a scanner run is currently active.
    """

    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    uptime_seconds: int = 0
    commands_intercepted: int = 0
    commands_blocked: int = 0
    threats_blocked: int = 0
    current_mood: str = "HAPPY"
    recent_events: list = field(default_factory=list)
    last_event_message: str = ""
    # V2 fields
    last_scan_time: float = 0.0
    last_scan_type: str = ""
    last_scan_files_scanned: int = 0
    last_scan_threats_found: int = 0
    files_quarantined: int = 0
    last_threat_name: str = ""
    last_scan_duration: float = 0.0
    scan_in_progress: bool = False
    # V3 RL fields
    rl_steps_trained: int = 0
    rl_last_action: str = ""
    rl_last_confidence: float = 0.0
    rl_avg_reward: float = 0.0
    rl_state: str = "DISABLED"  # DISABLED, WARMUP, TRAINING
