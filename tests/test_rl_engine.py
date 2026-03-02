"""Tests for RLEngine."""

from __future__ import annotations

import os
import tempfile
import unittest
import builtins
from unittest.mock import MagicMock, patch

from cyberpet.events import Event, EventBus, EventType


class _FakeFPMemory:
    def export_for_rl(self):
        return {}
    def get_all_false_positives(self):
        return []
    def is_known_false_positive(self, sha256, filepath):
        return False
    def record_quarantine_confirmation(self, rec):
        pass


class _FakeScanHistory:
    def get_scan_history(self, limit=100):
        return []
    def get_threats_for_scan(self, scan_id):
        return []


class _FakeConfig:
    def __init__(self, model_dir, allow_network_actions=True):
        self.rl = {
            "enabled": True,
            "model_path": model_dir,
            "decision_interval_seconds": 30,
            "checkpoint_interval_steps": 100,
            "warmup_steps_no_priors": 100,
            "warmup_steps_with_priors": 50,
            "warmup_steps_deep_priors": 25,
            "deep_prior_threshold": 20,
            "allow_network_actions": allow_network_actions,
        }


class _PredictModel:
    def __init__(self, action: int):
        self._action = action

    def predict(self, _obs, deterministic=False):
        return self._action, None

    def learn(self, total_timesteps=0, reset_num_timesteps=False):
        return self


class _StepEnv:
    def __init__(self):
        self.last_action = None

    def reset(self):
        return [0.0] * 44, {}

    def step(self, action):
        self.last_action = action
        return [0.0] * 44, 0.0, False, False, {"confidence": 1.0}


class TestRLEngineInit(unittest.TestCase):
    """Verify engine initialization."""

    def test_fresh_model_creation(self) -> None:
        """Engine creates a new model when no saved file exists."""
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertIsNotNone(engine._model)
            self.assertEqual(engine._total_steps, 0)

    def test_warmup_default_100(self) -> None:
        """No priors → 100 step warmup."""
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertEqual(engine._warmup_steps, 100)

    def test_initialize_raises_when_sb3_missing(self) -> None:
        """Missing SB3 should fail fast so daemon doesn't run a dead RL loop."""
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)
            engine = RLEngine(config, bus, fp, hist)

            original_import = builtins.__import__

            def _fake_import(name, *args, **kwargs):
                if name == "stable_baselines3":
                    raise ImportError("simulated missing sb3")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=_fake_import):
                with self.assertRaises(RuntimeError):
                    engine.initialize()


class TestRLEngineModelPersistence(unittest.TestCase):
    """Verify model save/load."""

    def test_save_creates_file(self) -> None:
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()
            engine.save_checkpoint()

            model_file = os.path.join(tmpdir, "cyberpet_ppo.zip")
            self.assertTrue(os.path.exists(model_file))

    def test_load_restores_model(self) -> None:
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            # Save
            engine1 = RLEngine(config, bus, fp, hist)
            engine1.initialize()
            engine1._total_steps = 42
            engine1.save_checkpoint()

            # Load
            engine2 = RLEngine(config, bus, fp, hist)
            engine2.initialize()

            self.assertIsNotNone(engine2._model)


class TestRLEngineWarmup(unittest.TestCase):
    """Verify warmup period adjusts with priors."""

    def test_warmup_50_with_priors(self) -> None:
        """5+ confirmed threats → 50 steps."""
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        class _PopulatedHistory(_FakeScanHistory):
            def get_scan_history(self, limit=100):
                return [{"id": i} for i in range(5)]
            def get_threats_for_scan(self, scan_id):
                return [{"action_taken": "quarantined", "threat_category": "miner",
                         "threat_score": 80, "file_hash": f"h{scan_id}"}]

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _PopulatedHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertEqual(engine._warmup_steps, 50)

    def test_warmup_25_with_deep_priors(self) -> None:
        """20+ confirmed threats → 25 steps."""
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        class _DeepHistory(_FakeScanHistory):
            def get_scan_history(self, limit=100):
                return [{"id": i} for i in range(20)]
            def get_threats_for_scan(self, scan_id):
                return [{"action_taken": "quarantined", "threat_category": "miner",
                         "threat_score": 80, "file_hash": f"h{scan_id}"}]

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _DeepHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertEqual(engine._warmup_steps, 25)


class TestRLEngineFPEvents(unittest.TestCase):
    """T021: Verify FP_MARKED_SAFE event adds to safe_file_set immediately."""

    def test_fp_marked_safe_adds_to_set(self) -> None:
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertEqual(len(engine._safe_file_set), 0)
            engine.handle_fp_marked_safe("sha_abc", "/tmp/safe_file")
            self.assertIn(("sha_abc", "/tmp/safe_file"), engine._safe_file_set)

    def test_is_warmup_true_initially(self) -> None:
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertTrue(engine.is_warmup)
            self.assertEqual(engine.warmup_remaining, 100)

    def test_avg_reward_empty(self) -> None:
        try:
            from cyberpet.rl_engine import RLEngine
        except ImportError:
            self.skipTest("RL dependencies not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()

            self.assertEqual(engine.avg_reward, 0.0)


class TestRLEngineNetworkActionRemap(unittest.TestCase):
    """Ensure 4/7 are remapped when network actions are disabled."""

    def test_network_isolate_action_is_remapped_to_allow(self) -> None:
        from cyberpet.rl_engine import RLEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir, allow_network_actions=False)

            engine = RLEngine(config, bus, fp, hist)
            engine._initialized = True
            engine._warmup_steps = 0
            engine._total_steps = engine._learning_safe_steps + 1
            engine._model = _PredictModel(4)
            env = _StepEnv()
            engine._env = env

            step_info = engine.run_step()

            self.assertEqual(env.last_action, 0)
            self.assertEqual(step_info.get("action"), 0)
            self.assertEqual(step_info.get("action_name"), "ALLOW")


class TestRLEngineCheckpointing(unittest.TestCase):
    """Checkpoint behavior for step/time driven saves."""

    def test_run_step_triggers_checkpoint_when_time_due(self) -> None:
        from cyberpet.rl_engine import RLEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir, allow_network_actions=False)

            engine = RLEngine(config, bus, fp, hist)
            engine._initialized = True
            engine._warmup_steps = 0
            engine._total_steps = 1
            engine._model = _PredictModel(0)
            engine._env = _StepEnv()
            engine._checkpoint_interval = 100000
            engine._checkpoint_interval_seconds = 1
            engine._last_checkpoint_time = 0.0

            with patch.object(engine, "save_checkpoint") as save_mock:
                engine.run_step()
                save_mock.assert_called_once()

    def test_save_checkpoint_updates_last_checkpoint_time(self) -> None:
        from cyberpet.rl_engine import RLEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir)

            engine = RLEngine(config, bus, fp, hist)
            engine.initialize()
            before = engine._last_checkpoint_time
            engine.save_checkpoint()
            self.assertGreaterEqual(engine._last_checkpoint_time, before)

    def test_escalate_lockdown_action_is_remapped_to_allow(self) -> None:
        from cyberpet.rl_engine import RLEngine

        with tempfile.TemporaryDirectory() as tmpdir:
            bus = EventBus()
            fp = _FakeFPMemory()
            hist = _FakeScanHistory()
            config = _FakeConfig(tmpdir, allow_network_actions=False)

            engine = RLEngine(config, bus, fp, hist)
            engine._initialized = True
            engine._warmup_steps = 0
            engine._total_steps = engine._learning_safe_steps + 1
            engine._model = _PredictModel(7)
            env = _StepEnv()
            engine._env = env

            step_info = engine.run_step()

            self.assertEqual(env.last_action, 0)
            self.assertEqual(step_info.get("action"), 0)
            self.assertEqual(step_info.get("action_name"), "ALLOW")


if __name__ == "__main__":
    unittest.main()
