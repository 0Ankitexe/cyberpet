"""RL Decision Explainability for CyberPet V3.

Provides human-readable explanations for RL decisions by analysing
the state vector features and action outcomes.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from cyberpet.rl_engine import RLEngine
    from cyberpet.state_collector import SystemStateCollector
    from cyberpet.false_positive_memory import FalsePositiveMemory

logger = logging.getLogger("cyberpet.rl_explainer")

# State vector feature names (indices → human labels)
# Must match state_collector.py collect() exactly
FEATURE_LABELS: dict[int, str] = {
    0: "cpu_load_1min",
    1: "cpu_load_5min",
    2: "cpu_load_15min",
    3: "ram_percent",
    4: "swap_percent",
    5: "disk_io_rate",
    6: "process_count",
    7: "new_proc_events",
    8: "root_process_count",
    9: "unknown_process_count",
    10: "zombie_count",
    11: "thread_count",
    12: "connection_count",
    13: "outbound_bytes_rate",
    14: "new_conn_events",
    15: "external_connections",
    16: "failed_connections",
    17: "etc_modifications",
    18: "tmp_file_count",
    19: "tmp_executables",
    20: "cron_modified",
    21: "home_modifications",
    22: "threat_history_0",
    23: "threat_history_1",
    24: "threat_history_2",
    25: "threat_history_3",
    26: "threat_history_4",
    27: "threat_history_5",
    28: "threat_history_6",
    29: "threat_history_7",
    30: "cmds_blocked_rate",
    31: "cmds_warned_rate",
    32: "files_quarantined",
    33: "exec_blocks_rate",
    34: "last_scan_threats",
    35: "anomaly_score",
    36: "scan_in_progress",
    37: "time_sin_hour",
    38: "time_cos_hour",
    39: "time_sin_weekday",
    40: "time_cos_weekday",
    41: "business_hours",
    42: "pkg_verified_ratio",
    43: "fp_rate_recent",
}

ACTION_NAMES: dict[int, str] = {
    0: "ALLOW", 1: "LOG_WARN", 2: "BLOCK_PROCESS",
    3: "QUARANTINE_FILE", 4: "NETWORK_ISOLATE",
    5: "RESTORE_FILE", 6: "TRIGGER_SCAN", 7: "ESCALATE_LOCKDOWN",
}

# Feature indices with typical "elevated" thresholds
_ELEVATED_THRESHOLDS: dict[int, float] = {
    0: 0.8,   # cpu > 80%
    1: 0.85,  # ram > 85%
    7: 0.7,   # net_connections high
    22: 0.3,  # threat_history active
    35: 0.3,  # anomaly_score elevated
    43: 0.3,  # fp_rate high
}


class RLExplainer:
    """Explain RL decisions in human-readable terms.

    Can be used standalone (reads from config/state files) or
    with live engine and collector references.
    """

    def __init__(
        self,
        rl_engine: Any = None,
        state_collector: Any = None,
        fp_memory: Any = None,
    ) -> None:
        self._engine = rl_engine
        self._collector = state_collector
        self._fp = fp_memory

    def explain(
        self,
        action: int,
        state: Any = None,
        result: Any = None,
    ) -> str:
        """Generate human-readable explanation for an RL decision.

        Parameters
        ----------
        action : int
            The action index (0-7).
        state : np.ndarray | None
            The 44-feature observation vector at decision time.
        result : ActionResult | None
            The outcome of the action execution.

        Returns
        -------
        str
            Human-readable explanation string.
        """
        parts: list[str] = []
        action_name = ACTION_NAMES.get(action, f"ACTION_{action}")

        parts.append(f"Action: {action_name}")

        # Cite elevated features from the state vector
        if state is not None:
            elevated = []
            for idx, threshold in _ELEVATED_THRESHOLDS.items():
                if idx < len(state) and float(state[idx]) > threshold:
                    label = FEATURE_LABELS.get(idx, f"feature_{idx}")
                    val = float(state[idx])
                    elevated.append(f"{label}={val:.2f}")
            if elevated:
                parts.append(f"Elevated: {', '.join(elevated)}")

        # Add result context
        if result is not None:
            if getattr(result, "confirmed_threat", False):
                cat = getattr(result, "threat_category", "")
                parts.append(f"Outcome: threat confirmed ({cat})" if cat
                             else "Outcome: threat confirmed")
            elif getattr(result, "false_positive", False):
                parts.append("Outcome: false positive detected")
            elif getattr(result, "suspicious_detected", False):
                parts.append("Outcome: suspicious activity")
            else:
                parts.append("Outcome: no threat detected")

        # Warmup notice
        if self._engine and self._engine.is_warmup:
            remaining = self._engine.warmup_remaining
            parts.append(f"(warmup: {remaining} steps remaining)")

        return " | ".join(parts)

    def explain_fp_impact(self) -> str:
        """Analyse FP rate and its impact on RL behaviour.

        Returns a short analysis string suitable for CLI output.
        """
        if not self._fp:
            try:
                from cyberpet.false_positive_memory import FalsePositiveMemory
                self._fp = FalsePositiveMemory()
            except Exception:
                return ""

        try:
            entries = self._fp.get_all_false_positives()
            count = len(entries) if entries else 0

            if count == 0:
                return "No FP entries — RL brain operates without FP constraints."
            elif count < 5:
                return (f"{count} FP entries — minimal impact on RL behaviour. "
                        "Agent may be slightly conservative on known-safe files.")
            elif count < 20:
                return (f"{count} FP entries — moderate FP load. "
                        "Agent penalises actions against known-safe hashes. "
                        "Warmup period reduced.")
            else:
                return (f"{count} FP entries — significant FP history. "
                        "Agent is highly conservative. Consider reviewing "
                        "FP entries with 'cyberpet fp list'.")
        except Exception:
            return ""
