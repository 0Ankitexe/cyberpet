"""Structured logging for CyberPet.

Provides rotating log files, a separate threat log, and convenience
functions for logging at different levels.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Module-level loggers (initialized by setup_logging)
_main_logger: logging.Logger | None = None
_threat_logger: logging.Logger | None = None

# Log format: [TIMESTAMP] [LEVEL] [MODULE] message
LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Rotation settings
MAX_BYTES = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5


def setup_logging(
    log_path: str = "/var/log/cyberpet/",
    log_level: str = "INFO",
    debug_stdout: bool = False,
) -> None:
    """Initialize the logging system.

    Sets up the main logger and a separate threat logger, both
    with rotating file handlers.

    Args:
        log_path: Directory for log files.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
        debug_stdout: If True, also log to stdout.
    """
    global _main_logger, _threat_logger

    # Ensure log directory exists
    os.makedirs(log_path, exist_ok=True)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    level = getattr(logging, log_level.upper(), logging.INFO)

    # --- Main logger ---
    _main_logger = logging.getLogger("cyberpet")
    _main_logger.setLevel(level)
    _main_logger.handlers.clear()

    main_handler = RotatingFileHandler(
        os.path.join(log_path, "cyberpet.log"),
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
    )
    main_handler.setFormatter(formatter)
    _main_logger.addHandler(main_handler)

    if debug_stdout or log_level.upper() == "DEBUG":
        stdout_handler = logging.StreamHandler()
        stdout_handler.setFormatter(formatter)
        _main_logger.addHandler(stdout_handler)

    # --- Threat logger ---
    _threat_logger = logging.getLogger("cyberpet.threats")
    _threat_logger.setLevel(logging.WARNING)
    _threat_logger.handlers.clear()
    _threat_logger.propagate = True  # Also goes to main logger

    threat_handler = RotatingFileHandler(
        os.path.join(log_path, "threats.log"),
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
    )
    threat_handler.setFormatter(formatter)
    _threat_logger.addHandler(threat_handler)


def _get_main_logger() -> logging.Logger:
    """Return the main logger, initializing with defaults if needed."""
    global _main_logger
    if _main_logger is None:
        setup_logging()
    return _main_logger  # type: ignore[return-value]


def _get_threat_logger() -> logging.Logger:
    """Return the threat logger, initializing with defaults if needed."""
    global _threat_logger
    if _threat_logger is None:
        setup_logging()
    return _threat_logger  # type: ignore[return-value]


def log_info(message: str, module: str = "cyberpet") -> None:
    """Log an informational message.

    Args:
        message: The message to log.
        module: The source module name.
    """
    logger = _get_main_logger()
    logger_child = logger.getChild(module) if module != "cyberpet" else logger
    logger_child.info(message)


def log_warn(message: str, module: str = "cyberpet") -> None:
    """Log a warning message.

    Args:
        message: The message to log.
        module: The source module name.
    """
    logger = _get_main_logger()
    logger_child = logger.getChild(module) if module != "cyberpet" else logger
    logger_child.warning(message)


def log_error(message: str, module: str = "cyberpet") -> None:
    """Log an error message.

    Args:
        message: The message to log.
        module: The source module name.
    """
    logger = _get_main_logger()
    logger_child = logger.getChild(module) if module != "cyberpet" else logger
    logger_child.error(message)


def log_threat(message: str, module: str = "cyberpet") -> None:
    """Log a security threat to both main and threat-specific logs.

    Args:
        message: The threat description to log.
        module: The source module name.
    """
    threat_logger = _get_threat_logger()
    threat_child = threat_logger.getChild(module) if module != "cyberpet" else threat_logger
    threat_child.warning(f"THREAT: {message}")
