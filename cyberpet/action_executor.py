"""RL Action Executor for CyberPet V3.

Executes the 8 discrete RL actions with multi-layer false-positive
protection.  Before any blocking action the executor checks:
  1. Existing whitelist
  2. FalsePositiveMemory safe set
  3. Prior-knowledge safe hashes
If any match, the action is aborted with ``false_positive=True``.
"""

from __future__ import annotations

import asyncio  # Issue 5: single module-level import
import logging
import os
import time
import signal
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from cyberpet.events import Event, EventBus, EventType
from cyberpet.scan_trigger import append_trigger_command, read_trigger_commands

if TYPE_CHECKING:
    from cyberpet.false_positive_memory import FalsePositiveMemory
    from cyberpet.quarantine import QuarantineVault
    from cyberpet.rl_prior import RLPriorKnowledge
    from cyberpet.state import PetState

logger = logging.getLogger("cyberpet.action_executor")

# Action index → name
ACTION_NAMES: dict[int, str] = {
    0: "ALLOW",
    1: "LOG_WARN",
    2: "BLOCK_PROCESS",
    3: "QUARANTINE_FILE",
    4: "NETWORK_ISOLATE",
    5: "RESTORE_FILE",
    6: "TRIGGER_SCAN",
    7: "ESCALATE_LOCKDOWN",
}


@dataclass
class ActionResult:
    """Outcome of executing an RL action."""

    action: int = 0
    success: bool = True
    confirmed_threat: bool = False
    suspicious_detected: bool = False
    false_positive: bool = False
    target_in_fp_memory: bool = False
    threat_category: str = ""
    missed_threat: bool = False
    confidence_scale: float = 1.0
    scan_triggered: bool = False
    scan_attached: bool = False
    details: str = ""


class ActionExecutor:
    """Execute RL-selected actions with FP protection.

    Parameters
    ----------
    event_bus : EventBus
        For publishing action events.
    quarantine_vault : QuarantineVault | None
        Used by quarantine/restore actions.  Can be ``None`` in tests.
    fp_memory : FalsePositiveMemory
        Shared FP memory for safe-file checks.
    prior : RLPriorKnowledge
        Pre-loaded safe-file penalty set.
    pet_state : PetState
        Mutable runtime state.
    """

    def __init__(
        self,
        event_bus: EventBus,
        quarantine_vault: Any,
        fp_memory: Any,
        prior: Any,
        pet_state: Any,
        config: Any | None = None,
    ) -> None:
        self._bus = event_bus
        self._vault = quarantine_vault
        self._fp = fp_memory
        self._prior = prior
        self._pet = pet_state
        self._allow_network_actions = True
        if config is not None:
            try:
                rl_cfg = getattr(config, "rl", {})
                if hasattr(rl_cfg, "get"):
                    self._allow_network_actions = bool(
                        rl_cfg.get("allow_network_actions", False)
                    )
                elif isinstance(rl_cfg, dict):
                    self._allow_network_actions = bool(
                        rl_cfg.get("allow_network_actions", False)
                    )
                else:
                    self._allow_network_actions = False
            except Exception:
                self._allow_network_actions = False

        # Safe set from prior knowledge (sha256, filepath)
        try:
            self._safe_set: set[tuple[str, str]] = prior.get_safe_file_penalty_set()
        except Exception as exc:
            logger.warning(f"Failed to load safe set from priors: {exc}")
            self._safe_set = set()

        # Current target context, set externally before execute()
        self._current_target: dict[str, str] = {}

        # Dispatch table
        self._dispatch = {
            0: self._action_allow,
            1: self._action_log_warn,
            2: self._action_block_process,
            3: self._action_quarantine_file,
            4: self._action_network_isolate,
            5: self._action_restore_file,
            6: self._action_trigger_scan,
            7: self._action_escalate_lockdown,
        }

    def set_target(self, target: dict[str, str]) -> None:
        """Set current threat target context for next execute() call."""
        self._current_target = target

    def add_to_safe_set(self, sha256: str, filepath: str) -> None:
        """Add a file to the in-memory safe set (real-time FP update)."""
        self._safe_set.add((sha256, filepath))

    def execute(self, action: int) -> ActionResult:
        """Execute the given action index (0-7).

        Returns an ActionResult describing the outcome.
        """
        handler = self._dispatch.get(action, self._action_allow)
        return handler(action)

    # ── FP protection ──────────────────────────────────────────────────

    def _check_fp(self, action: int) -> ActionResult | None:
        """Check if current target is in any safe list.

        Returns an abort ActionResult if the target is safe, else None.
        """
        filepath = self._current_target.get("filepath", "")
        sha256 = self._current_target.get("sha256", "")

        # Check FP memory
        try:
            if filepath and self._fp.is_known_false_positive(sha256, filepath):
                logger.info(f"FP abort: {filepath} is in FP memory")
                return ActionResult(
                    action=action,
                    success=False,
                    false_positive=True,
                    target_in_fp_memory=True,
                    details=f"Aborted: {filepath} is in FP memory",
                )
        except Exception as exc:
            logger.debug(f"FP memory check failed: {exc}")

        # Check prior safe set
        if (sha256, filepath) in self._safe_set:
            logger.info(f"FP abort: {filepath} is in prior safe set")
            return ActionResult(
                action=action,
                success=False,
                false_positive=True,
                target_in_fp_memory=True,
                details=f"Aborted: {filepath} is in prior safe set",
            )

        # Check by hash alone
        for safe_sha, safe_path in self._safe_set:
            if sha256 and sha256 == safe_sha:
                return ActionResult(
                    action=action,
                    success=False,
                    false_positive=True,
                    target_in_fp_memory=True,
                    details=f"Aborted: hash {sha256[:8]} in safe set",
                )

        return None

    # ── Async event publishing helper ──────────────────────────────────

    def _publish_event(self, event: Event) -> None:
        """Publish event to EventBus, handling async context safely."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._bus.publish(event))
        except RuntimeError:
            logger.debug(f"No event loop to publish {event.type}")

    @staticmethod
    def _iptables_rule_exists(rule_args: list[str]) -> bool:
        """Check whether an iptables OUTPUT rule already exists."""
        try:
            res = subprocess.run(
                ["iptables", "-C", *rule_args],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return res.returncode == 0
        except Exception:
            return False

    @classmethod
    def _iptables_add_once(cls, rule_args: list[str]) -> bool:
        """Add an iptables rule once; no-op if already present."""
        if cls._iptables_rule_exists(rule_args):
            return False
        try:
            subprocess.run(
                ["iptables", "-A", *rule_args],
                capture_output=True,
                timeout=5,
                check=False,
            )
            return True
        except Exception:
            return False

    @classmethod
    def _iptables_delete_all(cls, rule_args: list[str]) -> int:
        """Delete all matching iptables rules and return delete count."""
        removed = 0
        while cls._iptables_rule_exists(rule_args):
            try:
                res = subprocess.run(
                    ["iptables", "-D", *rule_args],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode != 0:
                    break
                removed += 1
            except Exception:
                break
        return removed

    # ── Action implementations ─────────────────────────────────────────

    def _action_allow(self, action: int) -> ActionResult:
        return ActionResult(action=action, success=True, details="No action taken")

    def _action_log_warn(self, action: int) -> ActionResult:
        filepath = self._current_target.get("filepath", "unknown")
        logger.warning(f"RL LOG_WARN: suspicious activity on {filepath}")
        return ActionResult(
            action=action,
            success=True,
            suspicious_detected=True,
            details=f"Warning logged for {filepath}",
        )

    def _action_block_process(self, action: int) -> ActionResult:
        fp_check = self._check_fp(action)
        if fp_check:
            return fp_check

        pid = self._current_target.get("pid")
        if not pid:
            return ActionResult(
                action=action, success=False, details="No PID to block"
            )

        try:
            os.kill(int(pid), signal.SIGTERM)
            self._pet.threats_blocked += 1
            return ActionResult(
                action=action,
                success=True,
                confirmed_threat=True,
                threat_category=self._current_target.get("category", ""),
                details=f"Blocked process {pid}",
            )
        except (ProcessLookupError, PermissionError, ValueError) as exc:
            return ActionResult(
                action=action, success=False, details=f"Block failed: {exc}"
            )

    def _action_quarantine_file(self, action: int) -> ActionResult:
        fp_check = self._check_fp(action)
        if fp_check:
            return fp_check

        filepath = self._current_target.get("filepath", "")
        if not filepath or not os.path.exists(filepath):
            return ActionResult(
                action=action, success=False,
                details=f"File not found: {filepath}",
            )

        try:
            # Build a minimal threat record for the vault
            threat = type("ThreatRecord", (), {
                "filepath": filepath,
                "threat_score": int(self._current_target.get("threat_score", 50)),
                "threat_category": self._current_target.get("category", "rl_decision"),
                "threat_reason": "RL quarantine decision",
                "matched_rules": [],
                "sha256": self._current_target.get("sha256", ""),
            })()

            if self._vault:
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self._vault.quarantine_file(filepath, threat))
                except RuntimeError:
                    logger.warning("No event loop for quarantine — skipping async quarantine")

            self._pet.files_quarantined += 1

            # Record confirmation in FP memory
            try:
                self._fp.record_quarantine_confirmation(threat)
            except Exception as exc:
                logger.debug(f"Failed to record quarantine confirmation: {exc}")

            # Publish QUARANTINE_CONFIRMED event
            self._publish_event(Event(
                type=EventType.QUARANTINE_CONFIRMED,
                source="action_executor",
                data={"filepath": filepath,
                      "sha256": self._current_target.get("sha256", ""),
                      "category": self._current_target.get("category", "")},
                severity=70,
            ))

            return ActionResult(
                action=action,
                success=True,
                confirmed_threat=True,
                threat_category=self._current_target.get("category", ""),
                details=f"Quarantined {filepath}",
            )
        except Exception as exc:
            logger.error(f"Quarantine failed for {filepath}: {exc}")
            return ActionResult(
                action=action, success=False,
                details=f"Quarantine failed: {exc}",
            )

    def _action_network_isolate(self, action: int) -> ActionResult:
        fp_check = self._check_fp(action)
        if fp_check:
            return fp_check

        if not self._allow_network_actions:
            return ActionResult(
                action=action,
                success=True,
                details="Network actions disabled by config",
            )

        pid = self._current_target.get("pid", "")
        logger.warning(f"RL NETWORK_ISOLATE: restricting outbound for PID {pid}")

        # Attempt iptables-based isolation for the flagged PID
        if pid:
            try:
                uid = self._current_target.get("uid", "")
                if uid:
                    self._iptables_add_once(
                        ["OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"]
                    )
            except Exception as exc:
                logger.warning(f"iptables isolation failed: {exc}")

        # Publish LOCKDOWN_ACTIVATED event
        self._publish_event(Event(
            type=EventType.LOCKDOWN_ACTIVATED,
            source="action_executor",
            data={"action": "network_isolate", "pid": pid},
            severity=80,
        ))

        return ActionResult(
            action=action,
            success=True,
            confirmed_threat=True,
            details=f"Network isolation activated for PID {pid}",
        )

    def _action_restore_file(self, action: int) -> ActionResult:
        filepath = self._current_target.get("filepath", "unknown")
        logger.info(f"RL RESTORE_FILE: {filepath}")

        # Attempt restore from quarantine vault
        if self._vault and filepath != "unknown":
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._vault.restore_file(filepath))
            except (RuntimeError, AttributeError) as exc:
                logger.debug(f"Restore async failed: {exc}")

        # De-escalation: remove lockdown rules introduced by RL actions.
        uid = self._current_target.get("uid", "")
        if uid:
            self._iptables_delete_all(
                ["OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"]
            )
        self._iptables_delete_all(["OUTPUT", "-p", "tcp", "--dport", "1:1023", "-j", "DROP"])

        # Publish LOCKDOWN_DEACTIVATED event (restore = de-escalation)
        self._publish_event(Event(
            type=EventType.LOCKDOWN_DEACTIVATED,
            source="action_executor",
            data={"action": "restore_file", "filepath": filepath},
            severity=30,
        ))

        return ActionResult(
            action=action, success=True,
            details=f"Restore requested for {filepath}",
        )

    def _action_trigger_scan(self, action: int) -> ActionResult:
        trigger = "/var/run/cyberpet_scan_trigger"

        # If a scan is already running (typically user-triggered), RL scan
        # intent can attach to that run instead of requesting a second scan.
        try:
            if bool(getattr(self._pet, "scan_in_progress", False)):
                return ActionResult(
                    action=action,
                    success=True,
                    scan_attached=True,
                    details="Scan already active — attached to in-progress scan",
                )
        except Exception:
            pass

        # Cooldown: don't spam scans — check if one completed recently
        try:
            if hasattr(self, "_pet") and self._pet:
                last_scan = getattr(self._pet, "last_scan_time", 0)
                if last_scan and (time.time() - last_scan) < 300:
                    return ActionResult(
                        action=action, success=True,
                        details="Scan skipped (cooldown — last scan was <5 min ago)",
                    )
        except Exception:
            pass

        # Don't trigger if there's already a pending trigger
        try:
            existing = read_trigger_commands(trigger)
            if any(cmd in ("quick", "full", "quick_rl", "rl_quick") for cmd in existing):
                return ActionResult(
                    action=action, success=True,
                    scan_attached=True,
                    details="Scan already pending",
                )
        except OSError:
            pass

        try:
            append_trigger_command("quick_rl", trigger_file=trigger)
            return ActionResult(
                action=action, success=True,
                scan_triggered=True,
                details="Quick scan triggered",
            )
        except OSError:
            return ActionResult(
                action=action, success=True,
                details="Scan trigger attempted (file may not exist)",
            )

    def _action_escalate_lockdown(self, action: int) -> ActionResult:
        fp_check = self._check_fp(action)
        if fp_check:
            return fp_check

        if not self._allow_network_actions:
            return ActionResult(
                action=action,
                success=True,
                details="Network actions disabled by config",
            )

        logger.warning("RL ESCALATE_LOCKDOWN activated")

        # Kill suspicious processes if PIDs are known
        pid = self._current_target.get("pid", "")
        if pid:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, ValueError):
                pass

        # Block non-essential outbound network
        try:
            self._iptables_add_once(["OUTPUT", "-p", "tcp", "--dport", "1:1023", "-j", "DROP"])
        except Exception as exc:
            logger.warning(f"Lockdown iptables failed: {exc}")

        # Publish LOCKDOWN_ACTIVATED event
        self._publish_event(Event(
            type=EventType.LOCKDOWN_ACTIVATED,
            source="action_executor",
            data={"action": "escalate_lockdown", "pid": pid},
            severity=100,
        ))

        return ActionResult(
            action=action,
            success=True,
            confirmed_threat=True,
            details="System lockdown escalated",
        )
