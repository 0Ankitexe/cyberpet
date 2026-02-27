"""CyberPet Brain Screen — Dedicated RL brain detail view.

Full-screen modal accessible via 'b' from the main TUI.  Shows:
  - Reward trend graph (ASCII sparkline)
  - Action distribution (all 8 actions)
  - Decision log (scrollable, from RL_DECISION events)
  - Brain status panel (model info, FP impact, priors summary)
"""

from __future__ import annotations

import os
import json
import time
from collections import deque
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

# ── Constants ──────────────────────────────────────────────────────
ACTION_LABELS = [
    "ALLOW", "LOG_WARN", "BLOCK_PROCESS", "QUARANTINE_FILE",
    "NETWORK_ISOLATE", "RESTORE_FILE", "TRIGGER_SCAN", "ESCALATE_LOCKDOWN",
]

ACTION_COLORS = [
    "green", "yellow", "red", "bright_red",
    "magenta", "cyan", "blue", "bright_red",
]

ACTION_SHORT = ["ALW", "LOG", "BLK", "QRN", "NET", "RST", "SCN", "LCK"]


# ── Reward Graph Widget ───────────────────────────────────────────

class RewardGraphWidget(Static):
    """ASCII sparkline graph of recent rewards."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rewards: deque[float] = deque(maxlen=50)
        self._avg_reward: float = 0.0

    def push_reward(self, reward: float) -> None:
        self._rewards.append(reward)
        if self._rewards:
            self._avg_reward = sum(self._rewards) / len(self._rewards)
        self.refresh()

    def render(self) -> str:
        lines = ["┌─── Reward Trend (last 50 steps) ─────────────────────┐"]
        if not self._rewards:
            lines.append("│  No data yet — waiting for RL decisions...            │")
            for _ in range(6):
                lines.append("│                                                       │")
            lines.append(f"└───────────────────────────────────────────────────────┘")
            return "\n".join(lines)

        # Build sparkline
        rewards = list(self._rewards)
        min_r = min(min(rewards), -1)
        max_r = max(max(rewards), 1)
        rng = max_r - min_r or 1.0

        # 6 rows of graph
        graph_rows = 6
        graph_width = min(len(rewards), 50)
        grid = [[" "] * graph_width for _ in range(graph_rows)]

        for col, r in enumerate(rewards[-graph_width:]):
            row = int((r - min_r) / rng * (graph_rows - 1))
            row = max(0, min(graph_rows - 1, row))
            row = graph_rows - 1 - row  # invert for display
            char = "█" if r >= 0 else "▒"
            grid[row][col] = char

        # Zero line
        zero_row = graph_rows - 1 - int((0 - min_r) / rng * (graph_rows - 1))
        zero_row = max(0, min(graph_rows - 1, zero_row))

        for row_idx, row_data in enumerate(grid):
            row_str = "".join(row_data)
            label = f"{max_r - (row_idx / (graph_rows - 1)) * rng:>+6.1f}"
            if row_idx == zero_row:
                pad = 50 - len(row_str)
                line_content = f"{label} ┤{row_str}{'─' * max(0, pad)}"
            else:
                pad = 50 - len(row_str)
                line_content = f"{label} │{row_str}{' ' * max(0, pad)}"
            lines.append(f"│{line_content[:53]:53}│")

        avg_str = f"Avg: {self._avg_reward:+.2f}  |  Steps: {len(self._rewards)}"
        lines.append(f"│  {avg_str:<51}│")
        lines.append(f"└───────────────────────────────────────────────────────┘")
        return "\n".join(lines)


# ── Action Distribution Widget ────────────────────────────────────

class ActionDistWidget(Static):
    """Bar chart of action distribution."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._counts: dict[int, int] = {i: 0 for i in range(8)}

    def update_counts(self, counts: dict) -> None:
        for i in range(8):
            self._counts[i] = counts.get(i, counts.get(str(i), 0))
        self.refresh()

    def render(self) -> str:
        lines = ["┌─── Action Distribution ───────────────────────────────┐"]
        total = max(sum(self._counts.values()), 1)

        for i in range(8):
            count = self._counts.get(i, 0)
            pct = count / total * 100 if total > 0 else 0
            bar_len = int(pct / 100 * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            label = ACTION_SHORT[i]
            pct_str = f"{pct:5.1f}%"
            count_str = f"({count})"
            line = f"│  {label} {bar} {pct_str} {count_str:<6}│"
            lines.append(f"{line[:55]:55}│" if len(line) > 55 else line)

        lines.append(f"│  Total: {total:<44}│")
        lines.append("└───────────────────────────────────────────────────────┘")
        return "\n".join(lines)


# ── Decision Log Widget ───────────────────────────────────────────

class DecisionLogWidget(VerticalScroll):
    """Scrollable log of recent RL decisions."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._decisions: deque[dict] = deque(maxlen=50)
        self._dirty = False

    def add_decision(self, decision: dict) -> None:
        self._decisions.appendleft(decision)
        self._dirty = True

    def on_mount(self) -> None:
        self.set_interval(1.0, self._maybe_refresh)

    def _maybe_refresh(self) -> None:
        if self._dirty:
            self._dirty = False
            self._do_refresh()

    def _do_refresh(self) -> None:
        self.remove_children()
        for d in list(self._decisions)[:20]:
            step = d.get("step", "?")
            action = d.get("action_name", "?")
            reward = d.get("reward", 0.0)
            explanation = d.get("explanation", "")

            # Color by reward
            if reward > 0:
                style = "green"
            elif reward < -1:
                style = "red"
            else:
                style = "dim"

            header = f"#{step} {action:<18} {reward:>+6.1f}"
            entry = Text(header, style=style, no_wrap=True)
            self.mount(Static(entry))

            if explanation:
                # Truncate explanation
                expl_short = explanation[:60] + "..." if len(explanation) > 60 else explanation
                expl_text = Text(f"  {expl_short}", style="dim italic", no_wrap=True)
                self.mount(Static(expl_text))

        if not self._decisions:
            self.mount(Static(Text(
                "  No decisions yet — waiting for RL loop...",
                style="dim italic",
            )))

        self.scroll_home(animate=False)


# ── Brain Status Widget ───────────────────────────────────────────

class BrainStatusWidget(Static):
    """Static panel showing model info and brain health."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._model_path = ""
        self._model_size = ""
        self._model_updated = ""
        self._total_steps = 0
        self._avg_reward = 0.0
        self._rl_state = "DISABLED"
        self._warmup_remaining = 0
        self._fp_impact = ""
        self._prior_summary = ""

    def update_status(self, data: dict) -> None:
        self._total_steps = data.get("total_steps", self._total_steps)
        self._avg_reward = data.get("avg_reward", self._avg_reward)
        self._rl_state = data.get("rl_state", self._rl_state)
        self._warmup_remaining = data.get("warmup_remaining", self._warmup_remaining)
        self.refresh()

    def set_model_info(self, path: str, size: str, updated: str) -> None:
        self._model_path = path
        self._model_size = size
        self._model_updated = updated
        self.refresh()

    def set_fp_impact(self, text: str) -> None:
        self._fp_impact = text
        self.refresh()

    def set_prior_summary(self, text: str) -> None:
        self._prior_summary = text
        self.refresh()

    def render(self) -> str:
        lines = ["┌─── Brain Status ──────────────────────────────────────┐"]

        # State with color indicator
        state_display = self._rl_state
        if self._rl_state == "WARMUP":
            state_display = f"WARMUP ({self._warmup_remaining} steps left)"
        lines.append(f"│  State:    {state_display:<42}│")

        # Steps
        steps_fmt = f"{self._total_steps:,}"
        lines.append(f"│  Steps:    {steps_fmt:<42}│")

        # Reward
        lines.append(f"│  Reward:   {self._avg_reward:>+8.3f}{'':<34}│")

        lines.append("│                                                       │")

        # Model info
        if self._model_path:
            basename = os.path.basename(self._model_path)
            lines.append(f"│  Model:    {basename:<42}│")
            lines.append(f"│  Size:     {self._model_size:<42}│")
            lines.append(f"│  Updated:  {self._model_updated:<42}│")
        else:
            lines.append("│  Model:    Not found                                   │")

        lines.append("│                                                       │")

        # FP analysis
        if self._fp_impact:
            # Wrap to 50 chars
            words = self._fp_impact.split()
            fp_lines = []
            current = ""
            for w in words:
                if len(current) + len(w) + 1 > 49:
                    fp_lines.append(current)
                    current = w
                else:
                    current = f"{current} {w}" if current else w
            if current:
                fp_lines.append(current)
            lines.append("│  FP Impact:                                           │")
            for fl in fp_lines[:3]:
                lines.append(f"│    {fl:<49}│")

        # Prior summary
        if self._prior_summary:
            lines.append("│                                                       │")
            lines.append("│  Prior Knowledge:                                     │")
            ps = self._prior_summary[:49]
            lines.append(f"│    {ps:<49}│")

        lines.append("└───────────────────────────────────────────────────────┘")
        return "\n".join(lines)


# ── Brain Screen ──────────────────────────────────────────────────

class BrainScreen(Screen):
    """Full-screen RL brain detail view."""

    CSS = """
    BrainScreen {
        layout: vertical;
    }

    #brain-top-row {
        height: 45%;
        layout: horizontal;
    }

    #brain-bottom-row {
        height: 55%;
        layout: horizontal;
    }

    #reward-graph {
        width: 50%;
        height: 100%;
        border: round #00ff88;
        padding: 0 1;
    }

    #action-dist {
        width: 50%;
        height: 100%;
        border: round cyan;
        padding: 0 1;
    }

    #decision-log {
        width: 55%;
        height: 100%;
        border: round yellow;
        padding: 0 1;
    }

    #brain-info {
        width: 45%;
        height: 100%;
        border: round magenta;
        padding: 0 1;
    }
    """

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("b", "go_back", "Back"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._reward_graph = RewardGraphWidget(id="reward-graph")
        self._action_dist = ActionDistWidget(id="action-dist")
        self._decision_log = DecisionLogWidget(id="decision-log")
        self._brain_status = BrainStatusWidget(id="brain-info")

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="brain-top-row"):
            yield self._reward_graph
            yield self._action_dist
        with Horizontal(id="brain-bottom-row"):
            yield self._decision_log
            yield self._brain_status
        yield Footer()

    def on_mount(self) -> None:
        """Load initial model info."""
        self._load_model_info()
        self._load_state_file()

    def _load_model_info(self) -> None:
        """Read model file metadata."""
        try:
            from cyberpet.config import Config
            config = Config.load()
            model_dir = config.rl.get("model_path", "/var/lib/cyberpet/models/")
            model_file = os.path.join(model_dir, "cyberpet_ppo.zip")

            if os.path.exists(model_file):
                stat = os.stat(model_file)
                size = f"{stat.st_size / (1024 * 1024):.1f} MB"
                updated = time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime))
                self._brain_status.set_model_info(model_file, size, updated)
            else:
                self._brain_status.set_model_info("", "", "")
        except Exception:
            pass

        # FP impact
        try:
            from cyberpet.rl_explainer import RLExplainer
            explainer = RLExplainer()
            fp_text = explainer.explain_fp_impact()
            if fp_text:
                self._brain_status.set_fp_impact(fp_text)
        except Exception:
            pass

    def _load_state_file(self) -> None:
        """Read rl_state.json for initial data."""
        try:
            from cyberpet.config import Config
            config = Config.load()
            model_dir = config.rl.get("model_path", "/var/lib/cyberpet/models/")
            state_file = os.path.join(model_dir, "rl_state.json")

            if os.path.exists(state_file):
                with open(state_file) as f:
                    data = json.load(f)
                self._brain_status.update_status(data)
        except Exception:
            pass

    def push_decision(self, decision: dict) -> None:
        """Called by the main app when an RL_DECISION event arrives."""
        # Update reward graph
        reward = decision.get("reward", 0.0)
        self._reward_graph.push_reward(reward)

        # Update action distribution
        action = decision.get("action", 0)
        counts = self._action_dist._counts.copy()
        counts[action] = counts.get(action, 0) + 1
        self._action_dist.update_counts(counts)

        # Update decision log
        self._decision_log.add_decision(decision)

        # Update status
        self._brain_status.update_status({
            "total_steps": decision.get("step", 0),
            "avg_reward": decision.get("avg_reward", 0.0),
            "rl_state": "WARMUP" if decision.get("warmup", False) else "TRAINING",
            "warmup_remaining": decision.get("warmup_remaining", 0),
        })

    def action_go_back(self) -> None:
        """Return to main TUI."""
        self.app.pop_screen()
