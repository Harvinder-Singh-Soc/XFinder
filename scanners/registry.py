"""Scanner plugin registry.

Provides a single place to map scan-type identifiers (used by the CLI menu
and the scheduler) to ordered lists of scanner classes. Adding a new scanner
requires only:

1. Subclassing ``BaseScanner``.
2. Adding an entry in ``SCANNERS`` (either to an existing scan type or a
   brand-new scan type).

The orchestration engine reads ``SCANNERS`` and never imports concrete
scanner classes directly — this is what makes the architecture extensible.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Type

from scanners.base import BaseScanner
from scanners.dnsx import DnsxScanner
from scanners.httpx import HttpxScanner
from scanners.katana import KatanaScanner
from scanners.naabu import NaabuScanner
from scanners.nmap import NmapScanner
from scanners.nuclei import NucleiScanner
from scanners.subfinder import SubfinderScanner

#: Maps a scan-type identifier (string) to an ordered list of scanner classes.
#:
#: The order matters — downstream scanners depend on the cache populated by
#: upstream scanners (e.g. dnsx needs subdomains from subfinder).
SCANNERS: Dict[str, List[Type[BaseScanner]]] = {
    "subdomain":    [SubfinderScanner],
    "dns":          [SubfinderScanner, DnsxScanner],
    "cloud":        [SubfinderScanner, DnsxScanner, HttpxScanner],
    "port":         [SubfinderScanner, DnsxScanner, HttpxScanner, NaabuScanner],
    "webapi":       [SubfinderScanner, DnsxScanner, HttpxScanner, KatanaScanner],
    "vulnerability":[SubfinderScanner, DnsxScanner, HttpxScanner, NucleiScanner],
    "full":         [
        SubfinderScanner,
        DnsxScanner,
        HttpxScanner,
        NaabuScanner,
        NmapScanner,
        KatanaScanner,
        NucleiScanner,
    ],
}

#: Human-readable labels for the CLI menu.
SCAN_LABELS: Dict[str, str] = {
    "subdomain":     "Subdomain Discovery",
    "dns":           "DNS Enumeration",
    "cloud":         "Cloud Discovery",
    "port":          "Port Discovery",
    "webapi":        "Web/API Discovery",
    "vulnerability": "Vulnerability Scan",
    "full":          "Full Scan",
}


def get_scanner(scan_type: str) -> List[Type[BaseScanner]]:
    """Return the ordered list of scanner classes for *scan_type*.

    Raises ``KeyError`` if the scan type is unknown.
    """
    if scan_type not in SCANNERS:
        raise KeyError(f"Unknown scan type: {scan_type!r}. Valid: {list(SCANNERS)}")
    return SCANNERS[scan_type]


def list_scan_types() -> List[str]:
    """Return all registered scan types in a stable order."""
    # Preserve menu ordering
    return ["subdomain", "dns", "cloud", "port", "webapi", "vulnerability", "full"]
