"""RL Prior Knowledge Bootstrap for CyberPet V3.

Loads human-confirmed decisions from FalsePositiveMemory and ScanHistory
to give the RL model a head start. Called once during RLEngine.initialize()
before training begins.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cyberpet.false_positive_memory import FalsePositiveMemory
    from cyberpet.scan_history import ScanHistory

logger = logging.getLogger("cyberpet.rl_prior")


class RLPriorKnowledge:
    """Load confirmed human decisions to bootstrap the RL model.

    Reads FalsePositiveMemory (files marked safe, files confirmed as threats)
    and ScanHistory (scan results with per-threat actions) to produce:
    - A prior knowledge dict for reward function tuning
    - Action bias multipliers for warm-starting policy weights
    - A safe-file penalty set to prevent repeat false positives

    Usage::

        prior = RLPriorKnowledge(fp_memory, scan_history)
        data = prior.load()
        bias = prior.get_action_bias()
        safe_set = prior.get_safe_file_penalty_set()
        logger.info(prior.summarize())
    """

    def __init__(
        self,
        fp_memory: FalsePositiveMemory,
        scan_history: ScanHistory,
    ) -> None:
        self.fp_memory = fp_memory
        self.scan_history = scan_history
        self._cached: dict | None = None

    def load(self) -> dict:
        """Load prior knowledge from FP memory and scan history.

        Returns a dict with:
          safe_hashes, threat_hashes, safe_paths,
          fp_by_category, fp_by_rule,
          confirmed_threat_categories,
          total_fp_count, total_confirmed_threats,
          avg_threat_score_at_quarantine
        """
        try:
            fp_data = self.fp_memory.export_for_rl()
        except Exception:
            logger.warning("Failed to load FP memory for RL priors — starting fresh")
            fp_data = {}

        safe_hashes: set[str] = set(fp_data.get("safe_hashes", []))
        safe_paths: set[str] = set(fp_data.get("safe_paths", []))
        threat_hashes: set[str] = set(fp_data.get("confirmed_threats", []))
        fp_by_category: dict[str, int] = dict(fp_data.get("fp_categories", {}))
        fp_by_rule: dict[str, int] = dict(fp_data.get("fp_rules", {}))

        # Load quarantine confirmations from scan history
        confirmed_threat_categories: dict[str, int] = {}
        total_confirmed_threats = 0
        quarantine_scores: list[int] = []

        try:
            history = self.scan_history.get_scan_history(limit=100)
            for scan in history:
                scan_id = scan.get("id")
                if scan_id is None:
                    continue
                threats = self.scan_history.get_threats_for_scan(scan_id)
                for threat in threats:
                    action = threat.get("action_taken", "")
                    if action == "quarantined":
                        total_confirmed_threats += 1
                        cat = threat.get("threat_category", "unknown")
                        confirmed_threat_categories[cat] = (
                            confirmed_threat_categories.get(cat, 0) + 1
                        )
                        score = threat.get("threat_score", 0)
                        quarantine_scores.append(score)
                        file_hash = threat.get("file_hash", "")
                        if file_hash:
                            threat_hashes.add(file_hash)
        except Exception:
            logger.warning("Failed to load scan history for RL priors — using FP data only")

        avg_score = (
            sum(quarantine_scores) / len(quarantine_scores)
            if quarantine_scores
            else 0.0
        )

        self._cached = {
            "safe_hashes": safe_hashes,
            "threat_hashes": threat_hashes,
            "safe_paths": safe_paths,
            "fp_by_category": fp_by_category,
            "fp_by_rule": fp_by_rule,
            "confirmed_threat_categories": confirmed_threat_categories,
            "total_fp_count": len(safe_hashes),
            "total_confirmed_threats": total_confirmed_threats,
            "avg_threat_score_at_quarantine": avg_score,
        }
        return self._cached

    def get_action_bias(self) -> dict[int, float]:
        """Return action probability adjustments based on priors.

        Returns ``{action_index: bias_multiplier}`` where multiplier is
        0.5–2.0 (1.0 = no adjustment).

        Bias logic:
        - If many confirmed threats and few FPs → bias QUARANTINE (3) higher
        - If many FPs → bias ALLOW (0) higher, reduce QUARANTINE
        - Default: neutral (1.0 for all)
        """
        data = self._cached or self.load()
        bias: dict[int, float] = {i: 1.0 for i in range(8)}

        total_threats = data["total_confirmed_threats"]
        total_fps = data["total_fp_count"]

        if total_threats == 0 and total_fps == 0:
            return bias

        # If many confirmed threats relative to FPs, bias toward quarantine
        if total_threats > total_fps and total_threats >= 3:
            bias[3] = min(2.0, 1.0 + total_threats * 0.1)  # QUARANTINE_FILE
            bias[2] = min(1.5, 1.0 + total_threats * 0.05)  # BLOCK_PROCESS

        # If many FPs, bias toward caution
        if total_fps > total_threats and total_fps >= 3:
            bias[0] = min(1.5, 1.0 + total_fps * 0.05)  # ALLOW
            bias[3] = max(0.5, 1.0 - total_fps * 0.05)   # QUARANTINE_FILE

        return bias

    def get_safe_file_penalty_set(self) -> set[tuple[str, str]]:
        """Return set of (sha256, filepath) tuples that should receive
        -5 reward penalty if RL attempts to block/quarantine them.
        """
        data = self._cached or self.load()
        result: set[tuple[str, str]] = set()

        try:
            fp_records = self.fp_memory.get_all_false_positives()
            for record in fp_records:
                sha = record.get("sha256", "")
                path = record.get("filepath", "")
                if sha and path:
                    result.add((sha, path))
        except Exception:
            # Fallback: build from cached data
            for sha in data.get("safe_hashes", set()):
                result.add((sha, ""))
            for path in data.get("safe_paths", set()):
                result.add(("", path))

        return result

    def summarize(self) -> str:
        """Return human-readable summary for startup log."""
        data = self._cached or self.load()

        parts = [
            f"Loaded RL priors: {data['total_fp_count']} safe files, "
            f"{data['total_confirmed_threats']} confirmed threats",
        ]

        if data["fp_by_category"]:
            cats = ", ".join(
                f"{k}:{v}" for k, v in sorted(
                    data["fp_by_category"].items(), key=lambda x: -x[1]
                )[:3]
            )
            parts.append(f"FP categories ({cats})")

        if data["confirmed_threat_categories"]:
            cats = ", ".join(
                f"{k}:{v}" for k, v in sorted(
                    data["confirmed_threat_categories"].items(), key=lambda x: -x[1]
                )[:3]
            )
            parts.append(f"Threat categories ({cats})")

        return ". ".join(parts)
