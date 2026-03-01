"""CyberPet V3 RL Engine — PPO training loop and model persistence.

Orchestrates the full RL lifecycle:
  1. Load prior knowledge from human decisions
  2. Create or load a PPO model
  3. Run observation-action-reward cycles
  4. Save checkpoints periodically and on shutdown
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from typing import Any, TYPE_CHECKING

from cyberpet.events import Event, EventBus, EventType
from cyberpet.rl_prior import RLPriorKnowledge

if TYPE_CHECKING:
    from cyberpet.false_positive_memory import FalsePositiveMemory
    from cyberpet.scan_history import ScanHistory

logger = logging.getLogger("cyberpet.rl_engine")

# ── Constants ──────────────────────────────────────────────────────────
_MODEL_FILENAME = "cyberpet_ppo.zip"
_WARMUP_ACTIONS = {0, 1}             # ALLOW, LOG_WARN
_WARMUP_ACTIONS_WITH_THREATS = {0, 1, 3}  # + QUARANTINE_FILE

# Learning-Safe Mode: restrict destructive actions until this many steps
_DEFAULT_LEARNING_SAFE_STEPS = 500
_LEARNING_SAFE_ACTIONS = {0, 1, 5, 6}  # ALLOW, LOG_WARN, RESTORE, SCAN
_DESTRUCTIVE_FALLBACK = {              # destructive → safe fallback
    2: 1,  # BLOCK_PROCESS → LOG_WARN
    3: 1,  # QUARANTINE_FILE → LOG_WARN
    4: 0,  # NETWORK_ISOLATE → ALLOW
    7: 0,  # ESCALATE_LOCKDOWN → ALLOW
}

# Default PPO batch size (n_steps) — model trains after this many steps
_DEFAULT_N_STEPS = 512


class RLEngine:
    """PPO-based RL engine for CyberPet.

    Parameters
    ----------
    config : Config
        Application configuration (``config.rl`` section).
    event_bus : EventBus
        For publishing RL_DECISION events and subscribing to FP events.
    fp_memory : FalsePositiveMemory
        Shared false-positive store.
    scan_history : ScanHistory
        For loading prior knowledge.
    """

    def __init__(
        self,
        config: Any,
        event_bus: EventBus,
        fp_memory: Any,
        scan_history: Any,
    ) -> None:
        self._config = config
        self._bus = event_bus
        self._fp = fp_memory
        self._scan_history = scan_history

        # ── Config values ──
        rl_cfg = getattr(config, "rl", {})
        if isinstance(rl_cfg, dict):
            self._model_dir = rl_cfg.get("model_path", "/var/lib/cyberpet/models/")
            self._checkpoint_interval = rl_cfg.get("checkpoint_interval_steps", 240)
            self._warmup_no_priors = rl_cfg.get("warmup_steps_no_priors", 100)
            self._warmup_with_priors = rl_cfg.get("warmup_steps_with_priors", 50)
            self._warmup_deep = rl_cfg.get("warmup_steps_deep_priors", 25)
            self._deep_threshold = rl_cfg.get("deep_prior_threshold", 20)
            self._learning_safe_steps = rl_cfg.get("learning_safe_steps", _DEFAULT_LEARNING_SAFE_STEPS)
        else:
            self._model_dir = getattr(rl_cfg, "model_path", "/var/lib/cyberpet/models/")
            self._checkpoint_interval = getattr(rl_cfg, "checkpoint_interval_steps", 240)
            self._warmup_no_priors = getattr(rl_cfg, "warmup_steps_no_priors", 100)
            self._warmup_with_priors = getattr(rl_cfg, "warmup_steps_with_priors", 50)
            self._warmup_deep = getattr(rl_cfg, "warmup_steps_deep_priors", 25)
            self._deep_threshold = getattr(rl_cfg, "deep_prior_threshold", 20)
            self._learning_safe_steps = getattr(rl_cfg, "learning_safe_steps", _DEFAULT_LEARNING_SAFE_STEPS)

        # ── Runtime state ──
        self._model: Any | None = None
        self._env: Any | None = None
        self._prior: RLPriorKnowledge | None = None
        self._prior_data: dict = {}
        self._total_steps: int = 0
        self._warmup_steps: int = self._warmup_no_priors
        self._last_checkpoint_step: int = 0
        self._safe_file_set: set[tuple[str, str]] = set()
        self._action_counts: dict[int, int] = {i: 0 for i in range(8)}
        self._reward_history: deque[float] = deque(maxlen=1000)  # Issue 3: bounded
        self._initialized = False

        # Issue 1: Track steps since last PPO batch update
        self._n_steps: int = _DEFAULT_N_STEPS
        self._steps_since_train: int = 0

        # Issue 6: Action bias from prior knowledge
        self._action_bias: dict[int, float] = {i: 1.0 for i in range(8)}

    @property
    def total_steps(self) -> int:
        return self._total_steps

    @property
    def warmup_remaining(self) -> int:
        return max(0, self._warmup_steps - self._total_steps)

    @property
    def is_warmup(self) -> bool:
        return self._total_steps < self._warmup_steps

    @property
    def avg_reward(self) -> float:
        if not self._reward_history:
            return 0.0
        window = list(self._reward_history)[-100:]
        return sum(window) / len(window)

    @property
    def action_distribution(self) -> dict[int, int]:
        return dict(self._action_counts)

    def initialize(self) -> None:
        """Load priors, create/load PPO model, configure warmup."""
        # 1. Load prior knowledge
        self._prior = RLPriorKnowledge(self._fp, self._scan_history)
        self._prior_data = self._prior.load()
        logger.info(self._prior.summarize())

        # 2. Set warmup period based on priors
        threats = self._prior_data.get("total_confirmed_threats", 0)
        if threats >= self._deep_threshold:
            self._warmup_steps = self._warmup_deep
        elif threats > 0:
            self._warmup_steps = self._warmup_with_priors
        else:
            self._warmup_steps = self._warmup_no_priors

        logger.info(
            f"Warmup: {self._warmup_steps} steps "
            f"({threats} confirmed threats in history)"
        )

        # 3. Load safe file set
        try:
            self._safe_file_set = self._prior.get_safe_file_penalty_set()
        except Exception as exc:
            logger.warning(f"Failed to load safe file set: {exc}")
            self._safe_file_set = set()

        # 4. Load action bias from prior knowledge (Issue 6)
        try:
            self._action_bias = self._prior.get_action_bias()
            if any(v != 1.0 for v in self._action_bias.values()):
                logger.info(f"Action bias from priors: {self._action_bias}")
        except Exception as exc:
            logger.warning(f"Failed to load action bias: {exc}")
            self._action_bias = {i: 1.0 for i in range(8)}

        # 5. Create or load model
        os.makedirs(self._model_dir, exist_ok=True)
        model_path = os.path.join(self._model_dir, _MODEL_FILENAME)

        try:
            from stable_baselines3 import PPO
        except ImportError:
            logger.error("stable-baselines3 not installed — RL engine disabled")
            return

        if os.path.exists(model_path):
            try:
                self._model = PPO.load(model_path)
                logger.info(f"Loaded existing model from {model_path}")
            except Exception as exc:
                logger.warning(f"Failed to load model, creating fresh: {exc}")
                self._model = self._create_fresh_model()
        else:
            self._model = self._create_fresh_model()
            logger.info("Created fresh PPO model")

        # Read n_steps from the model so batch training aligns
        if self._model is not None:
            self._n_steps = getattr(self._model, "n_steps", _DEFAULT_N_STEPS)

        # Restore training progress from last session
        state_file = os.path.join(self._model_dir, "rl_state.json")
        if os.path.exists(state_file):
            try:
                with open(state_file) as f:
                    saved = json.load(f)
                saved_steps = saved.get("total_steps", 0)
                if saved_steps > 0:
                    self._total_steps = saved_steps
                    self._last_checkpoint_step = saved_steps
                    # Seed reward history with saved avg so IQ is correct
                    avg = saved.get("avg_reward", 0.0)
                    seed_count = min(saved_steps, 100)
                    for _ in range(seed_count):
                        self._reward_history.append(avg)
                    logger.info(
                        f"Restored training state: step {saved_steps}, "
                        f"avg_reward {avg:+.2f}"
                    )
            except Exception as exc:
                logger.warning(f"Failed to restore rl_state.json: {exc}")

        self._initialized = True

    def set_env(self, env: Any) -> None:
        """Set the gymnasium environment for training."""
        self._env = env
        if self._model is not None:
            self._model.set_env(env)

    def run_step(self) -> dict:
        """Run one observation → action → reward cycle.

        Returns a dict with step details for event publishing.
        """
        if not self._initialized or self._model is None or self._env is None:
            return {"error": "Engine not initialized"}

        # Observe
        obs, _ = self._env.reset()

        # Select action (with warmup restriction)
        action_raw, _ = self._model.predict(obs, deterministic=False)
        action = int(action_raw)

        # Warmup: restrict to safe actions
        if self.is_warmup:
            allowed = (
                _WARMUP_ACTIONS_WITH_THREATS
                if self._prior_data.get("total_confirmed_threats", 0) > 0
                else _WARMUP_ACTIONS
            )
            if action not in allowed:
                action = 0  # Fall back to ALLOW

        # Learning-Safe Mode: restrict destructive actions until enough steps
        elif self._total_steps < self._learning_safe_steps:
            if action not in _LEARNING_SAFE_ACTIONS:
                action = _DESTRUCTIVE_FALLBACK.get(action, 0)
                logger.debug(
                    f"Learning-safe: step {self._total_steps}/{self._learning_safe_steps}, "
                    f"redirected to action {action}"
                )

        # Step
        new_obs, reward, done, truncated, info = self._env.step(action)

        # Issue 6: Apply action bias from prior knowledge as reward multiplier
        bias = self._action_bias.get(action, 1.0)
        reward = float(reward) * bias

        # Issue 1: Batch training — PPO needs n_steps before it updates weights
        self._steps_since_train += 1
        if self._steps_since_train >= self._n_steps:
            try:
                self._model.learn(
                    total_timesteps=self._n_steps,
                    reset_num_timesteps=False,
                )
                logger.info(
                    f"PPO batch update completed at step {self._total_steps} "
                    f"(trained on {self._n_steps} samples, avg_reward={self.avg_reward:+.2f})"
                )
            except Exception as exc:
                # Issue 4: Log instead of swallowing
                logger.error(f"PPO training failed at step {self._total_steps}: {exc}")
            self._steps_since_train = 0

        # Update stats
        self._total_steps += 1
        self._action_counts[action] = self._action_counts.get(action, 0) + 1
        self._reward_history.append(float(reward))

        # Checkpoint
        if (
            self._total_steps - self._last_checkpoint_step
            >= self._checkpoint_interval
        ):
            self.save_checkpoint()

        from cyberpet.action_executor import ACTION_NAMES

        # Generate human-readable explanation
        explanation = ""
        try:
            from cyberpet.rl_explainer import RLExplainer
            explainer = RLExplainer(rl_engine=self)
            explanation = explainer.explain(action, obs, None)
        except Exception as exc:
            logger.debug(f"Explainer failed: {exc}")

        step_info = {
            "step": self._total_steps,
            "action": action,
            "action_name": ACTION_NAMES.get(action, "UNKNOWN"),
            "reward": float(reward),
            "avg_reward": self.avg_reward,
            "warmup": self.is_warmup,
            "warmup_remaining": self.warmup_remaining,
            "explanation": explanation,
            "details": info,
        }

        return step_info

    def save_checkpoint(self) -> None:
        """Save model to disk."""
        if self._model is None:
            return

        model_path = os.path.join(self._model_dir, _MODEL_FILENAME)
        try:
            self._model.save(model_path)
            self._last_checkpoint_step = self._total_steps
            logger.info(
                f"Checkpoint saved at step {self._total_steps}: {model_path}"
            )
        except Exception as exc:
            logger.error(f"Failed to save checkpoint: {exc}")

    def shutdown(self) -> None:
        """Save model and clean up on daemon shutdown."""
        if self._initialized:
            self.save_checkpoint()
            logger.info(
                f"RL engine shut down after {self._total_steps} steps, "
                f"avg reward: {self.avg_reward:.2f}"
            )

    def handle_fp_marked_safe(self, sha256: str, filepath: str) -> None:
        """Update safe set when user marks a file safe (FP_MARKED_SAFE event)."""
        self._safe_file_set.add((sha256, filepath))
        logger.info(f"Added to RL safe set: {filepath} ({sha256[:8]})")

    # ── Private ────────────────────────────────────────────────────────

    def _create_fresh_model(self) -> Any:
        # Issue 8: Import inside method with clear error
        try:
            from stable_baselines3 import PPO
        except ImportError as exc:
            raise RuntimeError(
                "stable-baselines3 is required for RL engine. "
                "Install with: pip install stable-baselines3"
            ) from exc

        try:
            import gymnasium
            import numpy as np
            from cyberpet.state_collector import STATE_DIM
        except ImportError as exc:
            raise RuntimeError(
                "gymnasium and numpy are required for RL engine. "
                "Install with: pip install gymnasium numpy"
            ) from exc

        # Create a temporary environment for model initialization
        if self._env is not None:
            env = self._env
        else:
            # Use a minimal dummy env for initial model creation
            env = _make_dummy_env()

        model = PPO(
            "MlpPolicy",
            env,
            learning_rate=3e-4,
            n_steps=512,
            batch_size=64,
            n_epochs=10,
            gamma=0.99,
            gae_lambda=0.95,
            clip_range=0.2,
            ent_coef=0.01,
            vf_coef=0.5,
            max_grad_norm=0.5,
            policy_kwargs={
                "net_arch": [256, 256],
            },
            verbose=0,
            device="cpu",
        )

        return model


def _make_dummy_env() -> Any:
    """Create a minimal gymnasium environment for PPO model initialization.

    Issue 8: Moved out of module-level try/except so errors are clear.
    """
    try:
        import gymnasium
        import numpy as np
        from cyberpet.state_collector import STATE_DIM
    except ImportError as exc:
        raise RuntimeError(
            "Cannot create dummy env: gymnasium/numpy not installed"
        ) from exc

    class _DummyEnv(gymnasium.Env):
        """Minimal gymnasium environment stub for PPO model creation."""

        def __init__(self) -> None:
            super().__init__()
            self.observation_space = gymnasium.spaces.Box(
                low=0.0, high=1.0, shape=(STATE_DIM,), dtype=np.float32,
            )
            self.action_space = gymnasium.spaces.Discrete(8)

        def reset(self, **kwargs):
            return np.zeros(STATE_DIM, dtype=np.float32), {}

        def step(self, action):
            return np.zeros(STATE_DIM, dtype=np.float32), 0.0, False, False, {}

        def render(self):
            pass

        def close(self):
            pass

    return _DummyEnv()
