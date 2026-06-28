"""Centralized logging configuration for XFinder.

All modules import ``get_logger(__name__)`` instead of calling
``logging.getLogger`` directly. This guarantees consistent formatting and
file output across the project.
"""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from config.settings import settings

_CONFIGURED: bool = False


def _configure_root_logger() -> None:
    """Attach console + rotating file handlers to the root logger.

    Idempotent – safe to call multiple times.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    log_level = getattr(logging, settings.log_level, logging.INFO)
    log_dir: Path = settings.log_path
    log_file = log_dir / "xfinder.log"

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(log_level)

    # Console handler – INFO and above.
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(fmt)
    root.addHandler(console)

    # Rotating file handler – 5 MB per file, 5 backups.
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except PermissionError:
        # File logging is best-effort; do not crash if we cannot write.
        root.warning("Could not open log file %s for writing.", log_file)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger.

    The first call configures the root logger; subsequent calls are cheap.
    """
    if not _CONFIGURED:
        _configure_root_logger()
    return logging.getLogger(name)


# Module-level convenience logger for code that does not need a named channel.
logger: logging.Logger = logging.getLogger("xfinder")
