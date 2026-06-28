"""WHOIS / RDAP enrichment.

Uses the free RDAP (Registration Data Access Protocol) endpoint first,
falling back to classic WHOIS via ``python-whois``. RDAP is preferred
because it returns structured JSON rather than free-text WHOIS records.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from utils.logger import get_logger

logger = get_logger(__name__)

RDAP_BASE = "https://rdap.org/domain/"
TIMEOUT = 15


def enrich(domain: str) -> Dict[str, Any]:
    """Retrieve WHOIS/RDAP data for *domain*.

    Returns a normalized dict with registrar, creation/expiration dates,
    name servers, and status. Returns ``{error: ...}`` on failure.
    """
    domain = domain.strip().lower().rstrip(".")
    result: Dict[str, Any] = {"domain": domain}

    # Try RDAP first
    rdap_data = _rdap_lookup(domain)
    if rdap_data:
        result.update(rdap_data)
        result["source"] = "rdap"
        return result

    # Fall back to python-whois
    whois_data = _whois_lookup(domain)
    if whois_data:
        result.update(whois_data)
        result["source"] = "whois"
        return result

    result["error"] = "No WHOIS/RDAP data available"
    return result


# --------------------------------------------------------------------------- RDAP

def _rdap_lookup(domain: str) -> Optional[Dict[str, Any]]:
    try:
        resp = requests.get(RDAP_BASE + domain, timeout=TIMEOUT, headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        logger.debug("RDAP lookup failed for %s: %s", domain, exc)
        return None

    out: Dict[str, Any] = {}

    # Registrar (from entities)
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [None, []])[1] if len(entity.get("vcardArray", [])) > 1 else []
            for entry in vcard:
                if entry and entry[0] == "fn":
                    out["registrar"] = entry[3]
                    break

    # Events (registration, expiration, last update)
    for ev in data.get("events", []):
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action == "registration":
            out["created"] = date
        elif action == "expiration":
            out["expires"] = date
        elif action == "last changed":
            out["updated"] = date

    # Nameservers
    nss = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
    if nss:
        out["name_servers"] = nss

    # Status
    status = data.get("status", [])
    if status:
        out["status"] = status

    return out


# --------------------------------------------------------------------------- WHOIS fallback

def _whois_lookup(domain: str) -> Optional[Dict[str, Any]]:
    try:
        import whois  # python-whois
    except ImportError:
        logger.debug("python-whois not installed; skipping WHOIS fallback")
        return None

    try:
        w = whois.whois(domain)
    except Exception as exc:  # noqa: BLE001
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None

    out: Dict[str, Any] = {}
    if w.registrar:
        out["registrar"] = w.registrar
    if w.creation_date:
        dates = w.creation_date if isinstance(w.creation_date, list) else [w.creation_date]
        out["created"] = dates[0].isoformat() if hasattr(dates[0], "isoformat") else str(dates[0])
    if w.expiration_date:
        dates = w.expiration_date if isinstance(w.expiration_date, list) else [w.expiration_date]
        out["expires"] = dates[0].isoformat() if hasattr(dates[0], "isoformat") else str(dates[0])
    if w.updated_date:
        dates = w.updated_date if isinstance(w.updated_date, list) else [w.updated_date]
        out["updated"] = dates[0].isoformat() if hasattr(dates[0], "isoformat") else str(dates[0])
    if w.name_servers:
        nss = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
        out["name_servers"] = [n.lower() for n in nss]
    if w.status:
        out["status"] = w.status if isinstance(w.status, list) else [w.status]
    return out
