"""Tests for CyberPetEnv gymnasium environment."""

from __future__ import annotations

import unittest
from dataclasses import dataclass, field
from unittest.mock import MagicMock

import numpy as np

from cyberpet.state_collector import STATE_DIM


# ── Lightweight stubs ──────────────────────────────────────────────────

@dataclass
class _ActionResult:
    action: int = 0
    success: bool = True
    confirmed_threat: bool = False
    suspicious_detected: bool = False
    false_positive: bool = False
    target_in_fp_memory: bool = False
    threat_category: str = ""
    missed_threat: bool = False
    confidence_scale: float = 1.0
    details: str = ""


def _make_collector(vec: np.ndarray | None = None):
    sc = MagicMock()
    if vec is None:
        vec = np.random.uniform(0, 1, (STATE_DIM,)).astype(np.float32)
    sc.collect.return_value = vec
    return sc


class TestCyberPetEnvSpaces(unittest.TestCase):
    """Verify observation and action space dimensions."""

    def _make_env(self, **kw):
        from cyberpet.rl_env import CyberPetEnv

        sc = _make_collector()
        ae = MagicMock()
        ae.execute.return_value = _ActionResult()
        fp = MagicMock()
        prior = MagicMock()
        prior.get_safe_file_penalty_set.return_value = set()
        prior.load.return_value = {"confirmed_threat_categories": {}}
        config = MagicMock()
        config.rl = {}
        return CyberPetEnv(sc, ae, fp, prior, config)

    def test_observation_space_shape(self) -> None:
        env = self._make_env()
        self.assertEqual(env.observation_space.shape, (STATE_DIM,))

    def test_action_space_n(self) -> None:
        env = self._make_env()
        self.assertEqual(env.action_space.n, 8)

    def test_reset_returns_valid_obs(self) -> None:
        env = self._make_env()
        obs, info = env.reset()
        self.assertEqual(obs.shape, (STATE_DIM,))
        self.assertTrue(np.all(obs >= 0.0))
        self.assertTrue(np.all(obs <= 1.0))

    def test_step_returns_5_tuple(self) -> None:
        env = self._make_env()
        env.reset()
        result = env.step(0)
        self.assertEqual(len(result), 5)
        obs, reward, done, truncated, info = result
        self.assertEqual(obs.shape, (STATE_DIM,))
        self.assertIsInstance(reward, float)
        self.assertIsInstance(done, bool)
        self.assertIsInstance(truncated, bool)


class TestCyberPetEnvRewards(unittest.TestCase):
    """Verify reward function logic."""

    def _make_env(self):
        from cyberpet.rl_env import CyberPetEnv

        sc = _make_collector()
        self.ae = MagicMock()
        self.ae.execute.return_value = _ActionResult()
        fp = MagicMock()
        prior = MagicMock()
        prior.get_safe_file_penalty_set.return_value = set()
        prior.load.return_value = {"confirmed_threat_categories": {}}
        config = MagicMock()
        config.rl = {}
        return CyberPetEnv(sc, self.ae, fp, prior, config)

    def test_confirmed_threat_positive_reward(self) -> None:
        from cyberpet.rl_env import CyberPetEnv

        env = self._make_env()
        state = np.zeros(STATE_DIM, dtype=np.float32)
        result = _ActionResult(
            action=3, confirmed_threat=True, threat_category="cryptominer"
        )
        reward = env.calculate_reward(3, state, result)
        self.assertGreater(reward, 0.0)

    def test_false_positive_negative_reward(self) -> None:
        env = self._make_env()
        state = np.zeros(STATE_DIM, dtype=np.float32)
        result = _ActionResult(action=3, false_positive=True)
        reward = env.calculate_reward(3, state, result)
        self.assertLess(reward, 0.0)

    def test_fp_in_memory_extra_penalty(self) -> None:
        env = self._make_env()
        state = np.zeros(STATE_DIM, dtype=np.float32)
        result_fp = _ActionResult(action=3, false_positive=True, target_in_fp_memory=False)
        result_fp_mem = _ActionResult(action=3, false_positive=True, target_in_fp_memory=True)
        r1 = env.calculate_reward(3, state, result_fp)
        r2 = env.calculate_reward(3, state, result_fp_mem)
        self.assertLess(r2, r1)  # extra penalty for FP in memory

    def test_unnecessary_action_penalty(self) -> None:
        env = self._make_env()
        state = np.zeros(STATE_DIM, dtype=np.float32)
        state[30] = 0.01  # very low threat
        result = _ActionResult(action=2)  # BLOCK_PROCESS when no threat
        reward = env.calculate_reward(2, state, result)
        self.assertLess(reward, 0.0)


if __name__ == "__main__":
    unittest.main()
