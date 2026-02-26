"""ASCII art for CyberPet mood faces.

Defines ASCII art for each of the 7 moods.
Each face is 5 lines tall and fits within 20 characters wide.
"""

from __future__ import annotations


# ASCII faces per mood (5 lines each)
_FACES: dict[str, str] = {
    "SLEEPING": (
        "╭─────╮\n"
        "│ -.- │\n"
        "│  ω  │\n"
        "╰─────╯\n"
        " zzz..."
    ),
    "HAPPY": (
        "╭─────╮\n"
        "│ ^‿^ │\n"
        "│ \\_/ │\n"
        "╰─────╯\n"
        "  ~♪~  "
    ),
    "ALERT": (
        "╭─────╮\n"
        "│ O.O │\n"
        "│  !  │\n"
        "╰─────╯\n"
        "  ...  "
    ),
    "SUSPICIOUS": (
        "╭─────╮\n"
        "│ >_< │\n"
        "│ ??? │\n"
        "╰─────╯\n"
        "  hmm  "
    ),
    "AGGRESSIVE": (
        "╭─────╮\n"
        "│ >:[ │\n"
        "│ !!! │\n"
        "╰─────╯\n"
        " STOP! "
    ),
    "CRITICAL": (
        "╭─────╮\n"
        "│ x_x │\n"
        "│ !!  │\n"
        "╰─────╯\n"
        " ALERT!"
    ),
    "HEALING": (
        "╭─────╮\n"
        "│ ◕‿◕ │\n"
        "│ [+] │\n"
        "╰─────╯\n"
        " heal~ "
    ),
}


class MoodArt:
    """ASCII art manager for CyberPet moods.

    Stores all faces as multi-line strings and provides
    accessor methods.

    Usage:
        art = MoodArt()
        print(art.get_face("HAPPY"))
        print(art.list_moods())
    """

    def get_face(self, mood: str) -> str:
        """Get the ASCII face for a mood.

        Args:
            mood: The mood name (e.g., "HAPPY", "ALERT").

        Returns:
            Multi-line ASCII art string for the mood.
            Falls back to HAPPY if the mood is not found.
        """
        return _FACES.get(mood.upper(), _FACES["HAPPY"])

    def list_moods(self) -> list[str]:
        """List all available mood names.

        Returns:
            List of mood name strings.
        """
        return list(_FACES.keys())
