"""CyberPet V3 RL Engine — PPO training loop and model persistence.

Orchestrates the full RL lifecycle:
  1. Load prior knowledge from human decisions
  2. Create or load a PPO model
  3. Run observation-action-reward cycles
  4. Save checkpoints periodically and on shutdown
"""

from __future__ import annotations

import logging
import os
import time
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
            self._checkpoint_interval = rl_cfg.get("checkpoint_interval_steps", 3600)
            self._warmup_no_priors = rl_cfg.get("warmup_steps_no_priors", 100)
            self._warmup_with_priors = rl_cfg.get("warmup_steps_with_priors", 50)
            self._warmup_deep = rl_cfg.get("warmup_steps_deep_priors", 25)
            self._deep_threshold = rl_cfg.get("deep_prior_threshold", 20)
        else:
            self._model_dir = getattr(rl_cfg, "model_path", "/var/lib/cyberpet/models/")
            self._checkpoint_interval = getattr(rl_cfg, "checkpoint_interval_steps", 3600)
            self._warmup_no_priors = getattr(rl_cfg, "warmup_steps_no_priors", 100)
            self._warmup_with_priors = getattr(rl_cfg, "warmup_steps_with_priors", 50)
            self._warmup_deep = getattr(rl_cfg, "warmup_steps_deep_priors", 25)
            self._deep_threshold = getattr(rl_cfg, "deep_prior_threshold", 20)

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
        self._reward_history: list[float] = []
        self._initialized = False

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
        window = self._reward_history[-100:]
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
        except Exception:
            self._safe_file_set = set()

        # 4. Create or load model
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

        # Step
        new_obs, reward, done, truncated, info = self._env.step(action)

        # Train
        if hasattr(self._model, "learn"):
            try:
                self._model.learn(total_timesteps=1, reset_num_timesteps=False)
            except Exception:
                pass

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

        # T042: Generate human-readable explanation
        explanation = ""
        try:
            from cyberpet.rl_explainer import RLExplainer
            explainer = RLExplainer(rl_engine=self)
            explanation = explainer.explain(action, obs, None)
        except Exception:
            pass

        step_info = {
            "step": self._total_steps,
            "action": action,
            "action_name": ACTION_NAMES.get(action, "UNKNOWN"),
            "reward": float(reward),
            "avg_reward": self.avg_reward,
            "warmup": self.is_warmup,
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
        from stable_baselines3 import PPO

        # Create a temporary environment for model initialization
        if self._env is not None:
            env = self._env
        else:
            # Use the dummy env for initial model creation
            env = _DummyEnv()

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


try:
    import gymnasium as _gymnasium
    import numpy as _np
    from cyberpet.state_collector import STATE_DIM as _STATE_DIM

    class _DummyEnv(_gymnasium.Env):
        """Minimal gymnasium environment stub for PPO model creation."""

        def __init__(self) -> None:
            super().__init__()
            self.observation_space = _gymnasium.spaces.Box(
                low=0.0, high=1.0, shape=(_STATE_DIM,), dtype=_np.float32,
            )
            self.action_space = _gymnasium.spaces.Discrete(8)

        def reset(self, **kwargs):
            return _np.zeros(_STATE_DIM, dtype=_np.float32), {}

        def step(self, action):
            return _np.zeros(_STATE_DIM, dtype=_np.float32), 0.0, False, False, {}

        def render(self):
            pass

        def close(self):
            pass

except ImportError:
    _DummyEnv = None  # type: ignore[assignment,misc]
