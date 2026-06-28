"""Backwards-compatible re-export of ``config.settings``.

The project structure document lists both ``config.py`` and
``config/settings.py``. This top-level shim lets callers do either::

    from config import settings    # works (re-exported here)
    from config.settings import settings  # also works

Both forms return the same singleton instance.
"""

from config.settings import (  # noqa: F401
    APP_DESCRIPTION,
    APP_NAME,
    APP_VERSION,
    PROJECT_ROOT,
    SCHEDULER_STATE_FILE,
    Settings,
    get_settings,
    settings,
)

__all__ = [
    "APP_NAME",
    "APP_VERSION",
    "APP_DESCRIPTION",
    "PROJECT_ROOT",
    "SCHEDULER_STATE_FILE",
    "Settings",
    "get_settings",
    "settings",
]
