"""CyberPet Gymnasium Environment for V3 RL brain.

Custom gymnasium environment that wraps the CyberPet system state and
action execution.  The RL engine interacts with this environment every
decision cycle (default 30 s).
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

import gymnasium as gym
import numpy as np
from gymnasium import spaces

from cyberpet.state_collector import STATE_DIM

if TYPE_CHECKING:
    from cyberpet.action_executor import ActionExecutor, ActionResult
    from cyberpet.false_positive_memory import FalsePositiveMemory
    from cyberpet.rl_prior import RLPriorKnowledge
    from cyberpet.state_collector import SystemStateCollector

logger = logging.getLogger("cyberpet.rl_env")

# Action index → human name
ACTIONS: dict[int, str] = {
    0: "ALLOW",
    1: "LOG_WARN",
    2: "BLOCK_PROCESS",
    3: "QUARANTINE_FILE",
    4: "NETWORK_ISOLATE",
    5: "RESTORE_FILE",
    6: "TRIGGER_SCAN",
    7: "ESCALATE_LOCKDOWN",
}

# ── Issue 2: Named constants for state vector indices ──────────────────
# Must match state_collector.py collect() layout exactly.
IDX_THREAT_HISTORY_0 = 22   # Start of 8-slot threat history window
IDX_ANOMALY_SCORE = 35      # Heuristic anomaly score
IDX_FP_RATE_RECENT = 43     # Recent false positive rate


class CyberPetEnv(gym.Env):
    """Gymnasium environment for CyberPet RL.

    Observation space: Box(0, 1, shape=(44,), float32)
    Action space: Discrete(8)

    Parameters
    ----------
    state_collector : SystemStateCollector
        Provides the 44-feature observation vector.
    action_executor : ActionExecutor
        Executes the chosen action and returns ActionResult.
    fp_memory : FalsePositiveMemory
        Shared false-positive memory.
    prior : RLPriorKnowledge
        Prior knowledge from human decisions.
    config : Config
        Application configuration (uses ``config.rl`` section).
    """

    metadata = {"render_modes": []}

    def __init__(
        self,
        state_collector: Any,
        action_executor: Any,
        fp_memory: Any,
        prior: Any,
        config: Any,
    ) -> None:
        super().__init__()

        self.state_collector = state_collector
        self.action_executor = action_executor
        self.fp_memory = fp_memory
        self.prior = prior
        self.config = config

        # Spaces
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(STATE_DIM,), dtype=np.float32,
        )
        self.action_space = spaces.Discrete(8)

        # Load prior data for reward function
        try:
            self._prior_data = prior.load()
        except Exception as exc:
            logger.warning(f"Failed to load prior data for reward: {exc}")
            self._prior_data = {"confirmed_threat_categories": {}}

        # Safe file set from priors
        try:
            self.safe_file_set = prior.get_safe_file_penalty_set()
        except Exception as exc:
            logger.warning(f"Failed to load safe file set: {exc}")
            self.safe_file_set = set()

        # Current observation (cached between reset/step)
        self._current_obs: np.ndarray | None = None

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict | None = None,
    ) -> tuple[np.ndarray, dict]:
        """Reset environment and return initial observation."""
        super().reset(seed=seed)
        self._current_obs = self.state_collector.collect()
        return self._current_obs, {}

    def step(
        self, action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict]:
        """Execute one step: action → new observation + reward.

        Returns
        -------
        obs : np.ndarray
            New 44-feature observation.
        reward : float
            Scalar reward (clipped to [-20, 20]).
        terminated : bool
            Always False — environment is perpetual.
        truncated : bool
            Always False — no time limit.
        info : dict
            Action details for logging.
        """
        # Execute the action
        result = self.action_executor.execute(action)

        # Collect new state
        new_obs = self.state_collector.collect()

        # Calculate reward
        reward = self.calculate_reward(action, new_obs, result)

        self._current_obs = new_obs

        info = {
            "action_name": ACTIONS.get(action, "UNKNOWN"),
            "success": result.success,
            "false_positive": result.false_positive,
            "confirmed_threat": result.confirmed_threat,
            "details": result.details,
        }

        return new_obs, reward, False, False, info

    def calculate_reward(
        self,
        action: int,
        new_state: np.ndarray,
        action_result: Any,
    ) -> float:
        """Calculate reward from action outcome.

        Reward structure:
        - Confirmed threat neutralised: +10 (+ category bonus up to +2)
        - Suspicious caught: +5
        - System stability: +1
        - Correct inaction: +0.5
        - False positive: -5 (or -10 if in FP memory)
        - Unnecessary action: -3
        - Missed threat: -3
        - Disruptive action: -0.5
        - High FP rate: scales with rate × -3
        """
        reward = 0.0

        # Safety: ensure state vector is long enough
        has_threat = len(new_state) > IDX_THREAT_HISTORY_0
        has_anomaly = len(new_state) > IDX_ANOMALY_SCORE
        has_fp_rate = len(new_state) > IDX_FP_RATE_RECENT

        # === POSITIVE REWARDS ===

        # Confirmed threat neutralised
        if action_result.confirmed_threat and action in (2, 3, 7):
            base = 10.0
            cat = getattr(action_result, "threat_category", "")
            bonus = min(
                2.0,
                self._prior_data.get("confirmed_threat_categories", {}).get(cat, 0) * 0.2,
            )
            reward += base + bonus

        # Suspicious activity caught
        if action_result.suspicious_detected and action in (1, 2, 6):
            reward += 5.0

        # Scan action: reward both fresh trigger and attached intent.
        if action == 6 and action_result.success:
            if getattr(action_result, "scan_triggered", False):
                reward += 0.8
            elif getattr(action_result, "scan_attached", False):
                reward += 0.6

        # System stability (low anomaly + low threat)
        if has_anomaly and has_threat:
            if new_state[IDX_ANOMALY_SCORE] < 0.2 and new_state[IDX_THREAT_HISTORY_0] < 0.1:
                reward += 1.0

        # Correct inaction
        if action == 0 and has_threat and new_state[IDX_THREAT_HISTORY_0] < 0.1:
            reward += 0.5

        # === NEGATIVE REWARDS ===

        # False positive
        if action_result.false_positive:
            base_penalty = -5.0
            if action_result.target_in_fp_memory:
                base_penalty -= 5.0  # -10 total for repeat FP
            reward += base_penalty

        # Unnecessary action when no threat
        if action not in (0, 6) and not action_result.confirmed_threat and not action_result.suspicious_detected:
            if has_threat and new_state[IDX_THREAT_HISTORY_0] < 0.05:
                reward -= 3.0

        # Missed threat
        if action_result.missed_threat:
            reward -= 3.0

        # Disruptive action penalty
        if action in (4, 7):
            reward -= 0.5

        # High FP rate self-regulation
        if has_fp_rate:
            fp_rate = float(new_state[IDX_FP_RATE_RECENT])
            if fp_rate > 0.3 and action in (2, 3, 7):
                reward -= fp_rate * 3.0

        # Scale by confidence
        confidence = getattr(action_result, "confidence_scale", 1.0)
        reward *= confidence

        return float(np.clip(reward, -20.0, 20.0))
