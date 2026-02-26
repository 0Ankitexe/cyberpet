"""Scan menu modal for CyberPet TUI.

Presents Quick Scan / Full Scan / Cancel options.
Dismisses with the chosen scan type string ("quick" or "full")
or None if the user cancelled.
"""

from __future__ import annotations

from textual.app import ComposeResult  # type: ignore[import]
from textual.binding import Binding  # type: ignore[import]
from textual.containers import Vertical  # type: ignore[import]
from textual.screen import ModalScreen  # type: ignore[import]
from textual.widgets import Button, Static  # type: ignore[import]


class ScanMenuModal(ModalScreen[str | None]):
    """Modal screen for choosing scan type.

    Returns ``"quick"``, ``"full"``, or ``None`` (cancelled).
    """

    DEFAULT_CSS = """
    ScanMenuModal {
        align: center middle;
    }
    ScanMenuModal > Vertical {
        width: 48;
        height: auto;
        border: double $primary;
        padding: 1 2;
        background: $surface;
    }
    #scan-title {
        text-align: center;
        text-style: bold;
        color: $primary;
        padding-bottom: 1;
        width: 100%;
    }
    #btn-quick {
        width: 100%;
        margin-bottom: 1;
    }
    #btn-full {
        width: 100%;
        margin-bottom: 1;
    }
    #btn-cancel {
        width: 100%;
    }
    """

    BINDINGS = [
        Binding("q", "quick_scan", "Quick Scan", show=False),
        Binding("f", "full_scan", "Full Scan", show=False),
        Binding("escape", "cancel_menu", "Cancel", show=False),
    ]

    def compose(self) -> ComposeResult:  # type: ignore[override]
        with Vertical():
            yield Static("🛡  CyberPet SCAN", id="scan-title")
            yield Button(
                "⚡  QUICK SCAN  —  Dangerous files in /home + /root",
                id="btn-quick",
                variant="success",
            )
            yield Button(
                "🔍  FULL SCAN  —  Entire filesystem, all files",
                id="btn-full",
                variant="warning",
            )
            yield Button(
                "✕  CANCEL",
                id="btn-cancel",
                variant="default",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-quick":
            self.dismiss("quick")
        elif event.button.id == "btn-full":
            self.dismiss("full")
        else:
            self.dismiss(None)

    def action_quick_scan(self) -> None:
        self.dismiss("quick")

    def action_full_scan(self) -> None:
        self.dismiss("full")

    def action_cancel_menu(self) -> None:
        self.dismiss(None)
