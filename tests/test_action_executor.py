"""Tests for ActionExecutor."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from cyberpet.events import EventBus


class _FakeFPMemory:
    def __init__(self, safe_hashes=None):
        self._safe = safe_hashes or set()

    def is_known_false_positive(self, sha256: str, filepath: str) -> bool:
        return sha256 in self._safe or filepath in self._safe

    def record_quarantine_confirmation(self, threat_record) -> None:
        pass


class _FakePrior:
    def __init__(self, safe_set=None):
        self._safe_set = safe_set or set()

    def get_safe_file_penalty_set(self) -> set:
        return self._safe_set

    def load(self) -> dict:
        return {"confirmed_threat_categories": {}}


class TestActionExecutorBasics(unittest.TestCase):
    """Verify basic action execution."""

    def _make_executor(self, safe_hashes=None, safe_set=None):
        from cyberpet.action_executor import ActionExecutor

        bus = EventBus()
        vault = MagicMock()
        fp = _FakeFPMemory(safe_hashes=safe_hashes)
        prior = _FakePrior(safe_set=safe_set)

        from cyberpet.state import PetState
        pet = PetState()

        return ActionExecutor(bus, vault, fp, prior, pet)

    def test_allow_returns_success(self) -> None:
        ae = self._make_executor()
        result = ae.execute(0)
        self.assertTrue(result.success)
        self.assertEqual(result.action, 0)

    def test_log_warn_returns_success(self) -> None:
        ae = self._make_executor()
        result = ae.execute(1)
        self.assertTrue(result.success)

    def test_all_8_actions_return_result(self) -> None:
        ae = self._make_executor()
        for action_idx in range(8):
            result = ae.execute(action_idx)
            self.assertEqual(result.action, action_idx)
            self.assertIsInstance(result.success, bool)

    def test_action_result_has_required_fields(self) -> None:
        ae = self._make_executor()
        result = ae.execute(0)
        self.assertTrue(hasattr(result, "action"))
        self.assertTrue(hasattr(result, "success"))
        self.assertTrue(hasattr(result, "confirmed_threat"))
        self.assertTrue(hasattr(result, "false_positive"))
        self.assertTrue(hasattr(result, "target_in_fp_memory"))
        self.assertTrue(hasattr(result, "threat_category"))
        self.assertTrue(hasattr(result, "confidence_scale"))


class TestActionExecutorFPProtection(unittest.TestCase):
    """Verify false positive protection on blocking actions."""

    def _make_executor(self, safe_hashes=None, safe_set=None):
        from cyberpet.action_executor import ActionExecutor

        bus = EventBus()
        vault = MagicMock()
        fp = _FakeFPMemory(safe_hashes=safe_hashes)
        prior = _FakePrior(safe_set=safe_set)

        from cyberpet.state import PetState
        pet = PetState()

        return ActionExecutor(bus, vault, fp, prior, pet)

    def test_quarantine_fp_file_aborts(self) -> None:
        ae = self._make_executor(safe_hashes={"/tmp/safe_file"})
        ae._current_target = {"filepath": "/tmp/safe_file", "sha256": "abc"}
        result = ae.execute(3)  # QUARANTINE_FILE
        self.assertTrue(result.false_positive)
        self.assertTrue(result.target_in_fp_memory)

    def test_block_safe_hash_aborts(self) -> None:
        ae = self._make_executor(safe_set={("safe_sha", "/usr/bin/tool")})
        ae._current_target = {"filepath": "/usr/bin/tool", "sha256": "safe_sha"}
        result = ae.execute(2)  # BLOCK_PROCESS
        self.assertTrue(result.false_positive)


class TestActionExecutorUS2FPEnhancements(unittest.TestCase):
    """T020: Test FP memory abort, safe-set abort, and quarantine confirmation."""

    def _make_executor(self, safe_hashes=None, safe_set=None):
        from cyberpet.action_executor import ActionExecutor

        bus = EventBus()
        vault = MagicMock()
        self._fp = _FakeFPMemory(safe_hashes=safe_hashes)
        # Track calls to record_quarantine_confirmation
        self._fp.record_quarantine_confirmation = MagicMock()
        prior = _FakePrior(safe_set=safe_set)

        from cyberpet.state import PetState
        pet = PetState()

        return ActionExecutor(bus, vault, self._fp, prior, pet)

    def test_quarantine_fp_in_memory_aborts(self) -> None:
        ae = self._make_executor(safe_hashes={"/tmp/known_safe"})
        ae._current_target = {"filepath": "/tmp/known_safe", "sha256": "abc123"}
        result = ae.execute(3)
        self.assertTrue(result.false_positive)
        self.assertTrue(result.target_in_fp_memory)
        self.assertFalse(result.confirmed_threat)

    def test_quarantine_prior_safe_set_aborts(self) -> None:
        ae = self._make_executor(safe_set={("hash1", "/usr/lib/safe.so")})
        ae._current_target = {"filepath": "/usr/lib/safe.so", "sha256": "hash1"}
        result = ae.execute(3)
        self.assertTrue(result.false_positive)
        self.assertTrue(result.target_in_fp_memory)

    def test_network_isolate_fp_aborts(self) -> None:
        ae = self._make_executor(safe_hashes={"/opt/trusted"})
        ae._current_target = {"filepath": "/opt/trusted", "sha256": "safehash"}
        result = ae.execute(4)  # NETWORK_ISOLATE
        self.assertTrue(result.false_positive)

    def test_escalate_lockdown_fp_aborts(self) -> None:
        ae = self._make_executor(safe_set={("h", "/p")})
        ae._current_target = {"filepath": "/p", "sha256": "h"}
        result = ae.execute(7)  # ESCALATE_LOCKDOWN
        self.assertTrue(result.false_positive)

    def test_add_to_safe_set_prevents_future_block(self) -> None:
        ae = self._make_executor()
        ae.add_to_safe_set("new_sha", "/tmp/new_safe")
        ae._current_target = {"filepath": "/tmp/new_safe", "sha256": "new_sha"}
        result = ae.execute(3)  # QUARANTINE
        self.assertTrue(result.false_positive)


class TestActionExecutorUS4FullActions(unittest.TestCase):
    """T028: Test all 8 actions return valid ActionResult with details."""

    def _make_executor(self):
        from cyberpet.action_executor import ActionExecutor

        bus = EventBus()
        vault = MagicMock()
        fp = _FakeFPMemory()
        prior = _FakePrior()

        from cyberpet.state import PetState
        pet = PetState()

        return ActionExecutor(bus, vault, fp, prior, pet)

    def test_network_isolate_confirms_threat(self) -> None:
        ae = self._make_executor()
        ae._current_target = {"pid": "12345"}
        result = ae.execute(4)
        self.assertTrue(result.confirmed_threat)
        self.assertIn("isolation", result.details.lower())

    def test_escalate_lockdown_confirms_threat(self) -> None:
        ae = self._make_executor()
        result = ae.execute(7)
        self.assertTrue(result.confirmed_threat)
        self.assertIn("lockdown", result.details.lower())

    def test_restore_file_returns_success(self) -> None:
        ae = self._make_executor()
        ae._current_target = {"filepath": "/tmp/quarantined"}
        result = ae.execute(5)
        self.assertTrue(result.success)
        self.assertIn("restore", result.details.lower())

    def test_trigger_scan_returns_success(self) -> None:
        ae = self._make_executor()
        result = ae.execute(6)
        self.assertTrue(result.success)
        self.assertIn("scan", result.details.lower())

    def test_log_warn_detects_suspicious(self) -> None:
        ae = self._make_executor()
        result = ae.execute(1)
        self.assertTrue(result.suspicious_detected)

    def test_allow_no_threat(self) -> None:
        ae = self._make_executor()
        result = ae.execute(0)
        self.assertFalse(result.confirmed_threat)
        self.assertFalse(result.false_positive)


if __name__ == "__main__":
    unittest.main()
