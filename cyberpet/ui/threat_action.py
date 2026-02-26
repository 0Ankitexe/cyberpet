"""Threat action modal for CyberPet TUI.

Shows threat details and provides Quarantine / Mark Safe / Back actions.
Dismisses with a result dict describing the chosen action.
"""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult  # type: ignore[import]
from textual.binding import Binding  # type: ignore[import]
from textual.containers import Vertical  # type: ignore[import]
from textual.screen import ModalScreen  # type: ignore[import]
from textual.widgets import Button, Static  # type: ignore[import]

from cyberpet.scanner import ThreatRecord  # type: ignore[import]


def _threat_icon(score: int) -> str:
    if score >= 90:
        return "☠"
    if score >= 70:
        return "🔴"
    return "⚠"


class ThreatActionModal(ModalScreen[dict[str, Any] | None]):
    """Modal for acting on a single threat.

    Receives a ``ThreatRecord`` and returns::

        {"action": "quarantine" | "safe" | "back", "threat": ThreatRecord}
    """

    DEFAULT_CSS = """
    ThreatActionModal {
        align: center middle;
    }
    ThreatActionModal > Vertical {
        width: 58;
        height: auto;
        border: double $error;
        padding: 1 2;
        background: $surface;
    }
    #threat-title {
        text-align: center;
        text-style: bold;
        color: $error;
        padding-bottom: 1;
        width: 100%;
    }
    #threat-detail {
        padding: 0 0 1 0;
    }
    #btn-quarantine {
        width: 100%;
        margin-bottom: 1;
    }
    #btn-safe {
        width: 100%;
        margin-bottom: 1;
    }
    #btn-back {
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=False),
    ]

    def __init__(self, threat: ThreatRecord, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.threat = threat

    def compose(self) -> ComposeResult:  # type: ignore[override]
        t = self.threat
        icon = _threat_icon(t.threat_score)

        # Hash display — short form
        h = t.file_hash
        hash_display = (h[:8] + "…" + h[-8:]) if len(h) > 20 else (h or "N/A")

        # Reason truncated to 100 chars
        reason = t.threat_reason[:100] + "…" if len(t.threat_reason) > 100 else t.threat_reason

        detail = (
            f"  File:      {t.filepath}\n"
            f"  Score:     {t.threat_score} / 100\n"
            f"  Category:  {t.threat_category}\n"
            f"  Reason:    {reason}\n"
            f"  Hash:      {hash_display}"
        )

        with Vertical():
            yield Static(f"{icon}  THREAT DETECTED", id="threat-title")
            yield Static(detail, id="threat-detail")
            yield Button(
                "🔒  QUARANTINE  —  Move to secure vault",
                id="btn-quarantine",
                variant="error",
            )
            yield Button(
                "✅  MARK AS SAFE  —  This is a false positive",
                id="btn-safe",
                variant="success",
            )
            yield Button(
                "←  BACK",
                id="btn-back",
                variant="default",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-quarantine":
            self.dismiss({"action": "quarantine", "threat": self.threat})
        elif event.button.id == "btn-safe":
            self.dismiss({"action": "safe", "threat": self.threat})
        else:
            self.dismiss(None)

    def action_go_back(self) -> None:
        self.dismiss(None)
