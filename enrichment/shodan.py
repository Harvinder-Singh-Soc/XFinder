"""Shodan enrichment.

Looks up host information for a given IP via the Shodan REST API.

Requires ``SHODAN_API_KEY`` to be set in ``.env``. If absent, returns an
``error`` key instead of raising.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

SHODAN_BASE = "https://api.shodan.io/shodan/host/{ip}"
TIMEOUT = 15


def enrich(ip: str) -> Dict[str, Any]:
    """Query Shodan for information about *ip*.

    Returns a normalized dict with the most useful fields (ASN, org, country,
    open ports, services, vulnerabilities, tags). Returns ``{error: ...}``
    on failure or when the API key is missing.
    """
    if not settings.shodan_api_key:
        return {"ip": ip, "error": "SHODAN_API_KEY not configured"}

    result: Dict[str, Any] = {"ip": ip}
    try:
        resp = requests.get(
            SHODAN_BASE.format(ip=ip),
            params={"key": settings.shodan_api_key},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            result["error"] = "No Shodan data for this IP"
            return result
        if resp.status_code == 401:
            result["error"] = "Invalid Shodan API key"
            return result
        if resp.status_code == 429:
            result["error"] = "Shodan rate limit exceeded"
            return result
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.debug("Shodan lookup failed for %s: %s", ip, exc)
        result["error"] = f"Shodan request failed: {exc}"
        return result
    except ValueError as exc:
        result["error"] = f"Shodan returned invalid JSON: {exc}"
        return result

    # Normalize to a compact schema
    services = []
    for service in data.get("data", []):
        services.append({
            "port": service.get("port"),
            "transport": service.get("transport"),
            "service": service.get("_shodan", {}).get("module") or service.get("product"),
            "product": service.get("product"),
            "version": service.get("version"),
            "banner": (service.get("data") or "")[:500],  # truncate banners
        })

    result.update({
        "asn": data.get("asn"),
        "org": data.get("org"),
        "isp": data.get("isp"),
        "country_code": data.get("country_code"),
        "country_name": data.get("country_name"),
        "city": data.get("city"),
        "region": data.get("region_name"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "hostname": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "open_ports": sorted(set(s["port"] for s in services if s["port"])),
        "services": services,
        "tags": data.get("tags", []),
        "vulnerabilities": data.get("vulns", []),
        "last_update": data.get("last_update"),
        "os": data.get("os"),
    })
    return result
