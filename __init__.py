"""XFinder — External Attack Surface Management.

A modular Python EASM framework that orchestrates industry-standard
open-source tools (Subfinder, dnsx, httpx, Naabu, Nmap, Katana, Nuclei)
into an optimized scan pipeline, persists everything to PostgreSQL, and
supports scheduled rescans with change detection.

Top-level package; sub-modules:

* ``config``      — settings + DB engine
* ``scanners``    — tool wrappers + scan engine
* ``enrichment``  — asset enrichment modules
* ``database``    — ORM models + repository
* ``scheduler``   — APScheduler integration
* ``reports``     — JSON export + change detection
* ``utils``       — logger, helpers, validators

Entry point::

    python main.py
"""

from config.settings import APP_DESCRIPTION, APP_NAME, APP_VERSION

__version__ = APP_VERSION
__all__ = ["APP_NAME", "APP_VERSION", "APP_DESCRIPTION"]
