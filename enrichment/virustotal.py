"""VirusTotal reputation enrichment.

Uses the VirusTotal v3 API to look up domain reputation, last analysis
stats, and associated categories.

Requires ``VIRUSTOTAL_API_KEY`` to be set in ``.env``.
"""

from __future__ import annotations

from typing import Any, Dict

import requests

from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
TIMEOUT = 15


def enrich(domain: str) -> Dict[str, Any]:
    """Query VirusTotal v3 for reputation data on *domain*.

    Returns a normalized dict with reputation, last analysis stats,
    categories, and detected URLs/files counts.
    """
    if not settings.virustotal_api_key:
        return {"domain": domain, "error": "VIRUSTOTAL_API_KEY not configured"}

    domain = domain.strip().lower().rstrip(".")
    result: Dict[str, Any] = {"domain": domain}

    try:
        resp = requests.get(
            VT_DOMAIN_URL.format(domain=domain),
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            result["error"] = "Domain not in VirusTotal database"
            return result
        if resp.status_code == 401:
            result["error"] = "Invalid VirusTotal API key"
            return result
        if resp.status_code == 429:
            result["error"] = "VirusTotal rate limit exceeded"
            return result
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.debug("VirusTotal lookup failed for %s: %s", domain, exc)
        result["error"] = f"VirusTotal request failed: {exc}"
        return result
    except ValueError as exc:
        result["error"] = f"VirusTotal returned invalid JSON: {exc}"
        return result

    attrs = data.get("data", {}).get("attributes", {})
    if not attrs:
        result["error"] = "Empty VirusTotal response"
        return result

    last_analysis = attrs.get("last_analysis_stats", {})
    reputation = attrs.get("reputation")
    categories = attrs.get("categories", {})
    last_https_cert = attrs.get("last_https_certificate_date")
    favicon = attrs.get("favicon", {})

    result.update({
        "reputation": reputation,                          # signed int (positive = clean)
        "last_analysis_stats": {
            "harmless":     last_analysis.get("harmless", 0),
            "malicious":    last_analysis.get("malicious", 0),
            "suspicious":   last_analysis.get("suspicious", 0),
            "undetected":   last_analysis.get("undetected", 0),
            "timeout":      last_analysis.get("timeout", 0),
        },
        "categories": categories,
        "last_https_certificate_date": last_https_cert,
        "favicon": {
            "md5": favicon.get("md5"),
            "dhash": favicon.get("dhash"),
        } if favicon else None,
        "last_modification_date": attrs.get("last_modification_date"),
        "last_dns_records_date": attrs.get("last_dns_records_date"),
        "registrar": attrs.get("registrar"),
        "whois_date": attrs.get("whois_date"),
        "total_votes": attrs.get("total_votes", {}),
    })

    # Compute a simple verdict bucket for display purposes
    mal = last_analysis.get("malicious", 0)
    susp = last_analysis.get("suspicious", 0)
    if mal >= 5:
        result["verdict"] = "malicious"
    elif mal >= 1 or susp >= 3:
        result["verdict"] = "suspicious"
    elif last_analysis.get("harmless", 0) >= 10:
        result["verdict"] = "clean"
    else:
        result["verdict"] = "unknown"

    return result
