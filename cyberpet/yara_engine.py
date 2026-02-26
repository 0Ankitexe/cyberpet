"""YARA rules engine for CyberPet V2.

Compiles and caches YARA rules from a directory, providing file and
byte-buffer scanning with threat categorisation.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import yara  # type: ignore[import]

    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    """Result of a single YARA rule match."""

    rule_name: str
    category: str
    matched_strings: list[str] = field(default_factory=list)
    file_offset: int = 0


# Map YARA rule meta "category" values to standard threat categories
_CATEGORY_ALIASES: dict[str, str] = {
    "ransomware": "ransomware",
    "ransom": "ransomware",
    "miner": "cryptominer",
    "cryptominer": "cryptominer",
    "mining": "cryptominer",
    "webshell": "webshell",
    "web_shell": "webshell",
    "rat": "rat",
    "remote_access": "rat",
    "rootkit": "rootkit",
    "dropper": "dropper",
    "loader": "dropper",
    "generic": "unknown_malware",
    "malware": "unknown_malware",
    "trojan": "unknown_malware",
    "backdoor": "unknown_malware",
}


class YaraEngine:
    """Compile, cache, and scan with YARA rules.

    Rules are loaded from *rules_dir* and compiled once.  A cached
    compiled version is reused until any ``.yar`` or ``.yara`` file in
    the directory changes (detected via mtime).

    Usage:
        engine = YaraEngine("/etc/cyberpet/rules/")
        matches = engine.scan_file("/tmp/suspect.bin")
    """

    def __init__(
        self,
        rules_dir: str = "/etc/cyberpet/rules/",
        scan_timeout: int = 30,
    ) -> None:
        self.rules_dir = rules_dir
        self.scan_timeout = scan_timeout
        self._rules: Any | None = None
        self._last_mtime: float = 0.0

    @property
    def available(self) -> bool:
        """Return True if yara-python is importable."""
        return _YARA_AVAILABLE

    def _needs_recompile(self) -> bool:
        """Check if rule files changed since last compilation."""
        if self._rules is None:
            return True
        if not os.path.isdir(self.rules_dir):
            return False
        for entry in os.scandir(self.rules_dir):
            if entry.name.endswith((".yar", ".yara")):
                if entry.stat().st_mtime > self._last_mtime:
                    return True
        return False

    def compile_rules(self) -> bool:
        """Compile all .yar/.yara files in rules_dir.

        Returns:
            True if rules compiled successfully, False otherwise.
        """
        if not _YARA_AVAILABLE:
            return False
        if not os.path.isdir(self.rules_dir):
            return False

        filepaths: dict[str, str] = {}
        for entry in os.scandir(self.rules_dir):
            if entry.name.endswith((".yar", ".yara")):
                namespace = os.path.splitext(entry.name)[0]
                filepaths[namespace] = entry.path

        if not filepaths:
            return False

        try:
            self._rules = yara.compile(filepaths=filepaths)
            self._last_mtime = time.time()
            return True
        except yara.SyntaxError:
            # Try loading rules one-by-one, skip bad files
            good: dict[str, str] = {}
            for ns, fp in filepaths.items():
                try:
                    yara.compile(filepath=fp)
                    good[ns] = fp
                except Exception:
                    pass
            if good:
                self._rules = yara.compile(filepaths=good)
                self._last_mtime = time.time()
                return True
            return False
        except Exception:
            return False

    def _ensure_compiled(self) -> bool:
        """Recompile if needed.  Returns True if rules are available."""
        if self._needs_recompile():
            return self.compile_rules()
        return self._rules is not None

    def scan_file(self, filepath: str) -> list[YaraMatch]:
        """Scan a file with compiled YARA rules.

        Args:
            filepath: Absolute path to the file to scan.

        Returns:
            List of YaraMatch objects (empty if no matches or error).
        """
        if not self._ensure_compiled() or self._rules is None:
            return []
        try:
            raw_matches = self._rules.match(
                filepath=filepath, timeout=self.scan_timeout
            )
            return self._convert_matches(raw_matches)
        except Exception:
            return []

    def scan_bytes(self, data: bytes) -> list[YaraMatch]:
        """Scan a byte buffer with compiled YARA rules.

        Args:
            data: Raw bytes to scan.

        Returns:
            List of YaraMatch objects.
        """
        if not self._ensure_compiled() or self._rules is None:
            return []
        try:
            raw_matches = self._rules.match(data=data, timeout=self.scan_timeout)
            return self._convert_matches(raw_matches)
        except Exception:
            return []

    @staticmethod
    def _convert_matches(raw_matches: list) -> list[YaraMatch]:
        """Convert yara-python match objects to YaraMatch dataclasses."""
        results: list[YaraMatch] = []
        for m in raw_matches:
            meta = m.meta if hasattr(m, "meta") else {}
            category_raw = meta.get("category", "unknown_malware")
            category = _CATEGORY_ALIASES.get(
                str(category_raw).lower(), "unknown_malware"
            )
            strings: list[str] = []
            offset = 0
            if hasattr(m, "strings") and m.strings:
                for s in m.strings:
                    if hasattr(s, "identifier"):
                        strings.append(s.identifier)
                    elif isinstance(s, tuple) and len(s) >= 2:
                        offset = s[0] if isinstance(s[0], int) else 0
                        strings.append(str(s[1]))
            results.append(
                YaraMatch(
                    rule_name=m.rule,
                    category=category,
                    matched_strings=strings,
                    file_offset=offset,
                )
            )
        return results

    @staticmethod
    def categorize_matches(matches: list[YaraMatch]) -> str:
        """Determine overall threat category from a list of matches.

        Priority: ransomware > rootkit > rat > cryptominer > webshell > dropper > unknown_malware

        Args:
            matches: List of YaraMatch results.

        Returns:
            The highest-priority category found, or "unknown_malware".
        """
        priority = [
            "ransomware",
            "rootkit",
            "rat",
            "cryptominer",
            "webshell",
            "dropper",
            "unknown_malware",
        ]
        found = {m.category for m in matches}
        for cat in priority:
            if cat in found:
                return cat
        return "unknown_malware"
