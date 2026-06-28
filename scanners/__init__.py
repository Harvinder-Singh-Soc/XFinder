"""Scanner package — thin Python wrappers around external security tools.

Every scanner subclasses ``BaseScanner`` and exposes a ``run()`` method.
New scanners can be added by:

1. Creating ``scanners/my_tool.py`` with a ``MyToolScanner(BaseScanner)``.
2. Registering it in ``scanners/registry.py`` (optional, used by the CLI).

The core engine never imports concrete scanner classes directly — it works
through the ``BaseScanner`` interface — so plugins can be added without
touching the orchestration code.
"""

from scanners.base import BaseScanner
from scanners.registry import SCANNERS, get_scanner

__all__ = ["BaseScanner", "SCANNERS", "get_scanner"]
