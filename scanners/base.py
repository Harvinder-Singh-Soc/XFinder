"""Base class and plugin contract for all XFinder scanners.

The plugin contract is intentionally minimal:

* ``name``         – unique identifier (used by the CLI and scheduler).
* ``required_tools`` – list of binary names that must be on ``$PATH``.
* ``run(target: ScanContext) -> ScanResult`` – the actual scan.

``ScanContext`` carries everything a scanner needs: target domain, scan id,
and a shared cache to avoid duplicate work between scanners.
"""

from __future__ import annotations

import logging
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# --------------------------------------------------------------------------- context / result

@dataclass(slots=True)
class ScanContext:
    """Bundled parameters shared across all scanners in a single scan run."""

    target: str                       # canonical target domain (e.g. example.com)
    scan_id: int                      # database Scan.id
    target_id: int                    # database Target.id
    output_dir: str                   # absolute path to the per-scan output folder
    threads: int = 20
    timeout: int = 60
    rate: int = 1000
    cache: Dict[str, Any] = field(default_factory=dict)
    # Pre-populated inputs from earlier scanners (None until populated)
    subdomains: Optional[List[str]] = None
    live_hosts: Optional[List[str]] = None
    ports: Optional[Dict[str, List[int]]] = None  # ip -> [ports]


@dataclass(slots=True)
class ScanResult:
    """Standard return type for ``BaseScanner.run``."""

    scanner: str
    success: bool
    duration_seconds: float
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    raw_output: Optional[str] = None


# --------------------------------------------------------------------------- base class

class BaseScanner(ABC):
    """Abstract base class for every scanner plugin."""

    #: Human-readable name shown in the CLI.
    name: str = "base"
    #: Short description.
    description: str = ""
    #: External binaries that must exist on $PATH.
    required_tools: List[str] = []

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.log = get_logger(f"scanner.{self.name}")

    # ------------------------------------------------------------------ lifecycle

    def execute(self) -> ScanResult:
        """Template method: validate tools, time the run, capture exceptions.

        Subclasses implement ``run``; callers invoke ``execute`` so that
        timing and error handling are uniform.
        """
        missing = self.check_tools()
        if missing:
            msg = (
                f"Required tools not installed: {', '.join(missing)}. "
                f"Run `python install.py` to install missing dependencies."
            )
            self.log.error(msg)
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0, error=msg
            )

        self.log.info("Scanner [%s] starting for target=%s", self.name, self.ctx.target)
        start = time.time()
        try:
            result = self.run()
            duration = time.time() - start
            self.log.info(
                "Scanner [%s] finished in %.2fs (success=%s)",
                self.name, duration, result.success,
            )
            result.duration_seconds = duration
            return result
        except Exception as exc:  # noqa: BLE001 – top-level scanner guard
            duration = time.time() - start
            self.log.exception("Scanner [%s] failed: %s", self.name, exc)
            return ScanResult(
                scanner=self.name,
                success=False,
                duration_seconds=duration,
                error=str(exc),
            )

    @abstractmethod
    def run(self) -> ScanResult:
        """Perform the scan and return a ``ScanResult``."""
        raise NotImplementedError

    # ------------------------------------------------------------------ helpers

    @classmethod
    def check_tools(cls) -> List[str]:
        """Return list of required binaries missing from $PATH."""
        return [t for t in cls.required_tools if not shutil.which(t)]

    @classmethod
    def is_available(cls) -> bool:
        """True if all required external tools are installed."""
        return not cls.check_tools()
