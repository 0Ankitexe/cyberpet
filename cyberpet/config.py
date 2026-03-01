"""Configuration management for CyberPet.

Loads TOML config with fallback from system path to bundled default.
Provides attribute-style access and singleton pattern.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path
from typing import Any, cast

import toml  # type: ignore[import]


# System-wide config path (checked first)
SYSTEM_CONFIG_PATH = "/etc/cyberpet/config.toml"

# Bundled default config (fallback)
_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default_config.toml"

_FALLBACK_CONFIG: dict[str, Any] = {
    "general": {
        "pet_name": "Byte",
        "log_level": "INFO",
        "log_path": "/var/log/cyberpet/",
        "pid_file": "/var/run/cyberpet.pid",
        "event_stream_socket": "/var/run/cyberpet_events.sock",
        "event_stream_socket_mode": "0660",
        "event_stream_socket_group": "cyberpet",
    },
    "terminal_guard": {
        "enabled": True,
        "socket_path": "/var/run/cyberpet.sock",
        "socket_mode": "0660",
        "socket_group": "cyberpet",
        "block_threshold": 61,
        "hard_block_threshold": 86,
        "override_max_failures": 3,
        "allow_override_phrase": "CYBERPET ALLOW",
    },
    "ui": {
        "refresh_rate_ms": 500,
        "pet_name": "Byte",
        "show_allowed_events": False,
    },
    # V2 sections
    "scanner": {
        "quick_scan_interval_minutes": 30,
        "full_scan_time": "03:00",
        "max_file_size_mb": 50,
        "auto_quarantine": False,
        "auto_quarantine_threshold": 80,
    },
    "file_monitor": {
        "enabled": True,
        "monitored_paths": ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/lib"],
        "whitelist": [
            "apt", "apt-get", "dpkg", "dnf", "yum", "rpm",
            "pip", "pip3", "systemd", "systemctl", "sshd",
            "cron", "rsyslog",
        ],
    },
    "exec_monitor": {
        "enabled": True,
        "force_enable": False,
    },
    "yara": {
        "rules_dir": "/etc/cyberpet/rules/",
        "scan_timeout_seconds": 30,
    },
    "quarantine": {
        "vault_path": "/var/lib/cyberpet/quarantine/",
    },
    "hash_db": {
        "db_path": "/var/lib/cyberpet/hashes.db",
        "seed_file": "/etc/cyberpet/seed_hashes.csv",
    },
    "rl": {
        "enabled": True,
        "model_path": "/var/lib/cyberpet/models/",
        "decision_interval_seconds": 30,
        "checkpoint_interval_steps": 3600,
        "warmup_steps_no_priors": 100,
        "warmup_steps_with_priors": 50,
        "warmup_steps_deep_priors": 25,
        "deep_prior_threshold": 20,
        "learning_safe_steps": 500,
        "allow_network_actions": False,
    },
}


def _deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base* (in place)."""
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge_dicts(base[key], value)
        else:
            base[key] = value
    return base


class _ConfigSection:
    """A configuration section with attribute-style access.

    Wraps a dictionary to allow ``config.general.pet_name`` style access.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        """Return config value by attribute name.

        Args:
            name: The config key to look up.

        Returns:
            The config value, wrapped in _ConfigSection if it's a dict.

        Raises:
            AttributeError: If the key does not exist.
        """
        if name.startswith("_"):
            return super().__getattribute__(name)
        try:
            value = self._data[name]
            if isinstance(value, dict):
                return _ConfigSection(value)
            return value
        except KeyError:
            raise AttributeError(f"Config has no key '{name}'")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value with a fallback default.

        Args:
            key: The config key to look up.
            default: Value to return if key is not found.

        Returns:
            The config value or the default.
        """
        value = self._data.get(key, default)
        if isinstance(value, dict):
            return _ConfigSection(value)
        return value

    def __repr__(self) -> str:
        return f"ConfigSection({self._data})"


class Config(_ConfigSection):
    """Application configuration loaded from TOML (singleton).

    Checks ``/etc/cyberpet/config.toml`` first, then falls back to
    the bundled ``config/default_config.toml``.

    Usage:
        config = Config.load()
        name = config.general.pet_name
        threshold = config.terminal_guard.block_threshold
    """

    _instance: Config | None = None

    def __init__(self, data: dict[str, Any]) -> None:
        self._validate_terminal_guard_thresholds(data)
        super().__init__(data)

    @staticmethod
    def _validate_terminal_guard_thresholds(data: dict[str, Any]) -> None:
        """Normalize guard thresholds to safe/ordered values."""
        terminal_guard = data.get("terminal_guard")
        if not isinstance(terminal_guard, dict):
            return

        default_guard = _FALLBACK_CONFIG["terminal_guard"]

        def _to_int(value: Any, default: int) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        block_threshold = _to_int(
            terminal_guard.get("block_threshold", default_guard["block_threshold"]),
            int(default_guard["block_threshold"]),
        )
        hard_block_threshold = _to_int(
            terminal_guard.get("hard_block_threshold", default_guard["hard_block_threshold"]),
            int(default_guard["hard_block_threshold"]),
        )

        changed = False
        if block_threshold <= 30:
            block_threshold = 31
            changed = True
        if block_threshold >= 100:
            block_threshold = 99
            changed = True
        if hard_block_threshold > 100:
            hard_block_threshold = 100
            changed = True
        if hard_block_threshold <= block_threshold:
            hard_block_threshold = min(100, max(block_threshold + 1, int(default_guard["hard_block_threshold"])))
            changed = True
        if hard_block_threshold <= block_threshold:
            hard_block_threshold = min(100, block_threshold + 1)
            changed = True

        terminal_guard["block_threshold"] = block_threshold
        terminal_guard["hard_block_threshold"] = hard_block_threshold

        if changed:
            print(
                "[cyberpet] Adjusted invalid terminal_guard thresholds "
                f"(block_threshold={block_threshold}, hard_block_threshold={hard_block_threshold}).",
                file=sys.stderr,
            )

    @classmethod
    def load(cls, config_path: str | None = None) -> Config:
        """Load configuration (singleton — only loaded once).

        Args:
            config_path: Optional explicit path to config file.
                         If None, checks system path then bundled default.

        Returns:
            The singleton Config instance.
        """
        if cls._instance is not None:
            return cast(Config, cls._instance)

        path: Path | None = None

        if config_path:
            path = Path(config_path)
        elif os.path.exists(SYSTEM_CONFIG_PATH):
            path = Path(SYSTEM_CONFIG_PATH)
        elif _DEFAULT_CONFIG_PATH.exists():
            path = _DEFAULT_CONFIG_PATH

        if path and path.exists():
            try:
                loaded = toml.load(str(path))
                if isinstance(loaded, dict):
                    data = _deep_merge_dicts(copy.deepcopy(_FALLBACK_CONFIG), loaded)
                else:
                    data = copy.deepcopy(_FALLBACK_CONFIG)
            except (toml.TomlDecodeError, OSError) as exc:
                print(
                    f"[cyberpet] Failed to load config '{path}': {exc}. "
                    "Falling back to built-in defaults.",
                    file=sys.stderr,
                )
                data = copy.deepcopy(_FALLBACK_CONFIG)
        else:
            # Absolute fallback — minimal config
            data = copy.deepcopy(_FALLBACK_CONFIG)

        cls._instance = cls(data)
        return cast(Config, cls._instance)

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None

    def __repr__(self) -> str:
        return f"Config({self._data})"
