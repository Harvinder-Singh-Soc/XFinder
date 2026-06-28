"""ASN / organization / country enrichment.

We resolve ASN, organization, country, and hosting provider using the free
``origin.asn.cymru.com`` DNS service (Team Cymru). This avoids requiring a
paid IPinfo / Maxmind subscription.

Lookup process:

1. Reverse the IP octets (for IPv4) and query ``<reversed>.origin.asn.cymru.com`` TXT.
2. The TXT record contains ``AS | prefix | country | registry | date``.
3. Optionally resolve ``AS<asn>.asn.cymru.com`` TXT to get the organization
   name.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

import dns.resolver

from utils.logger import get_logger

logger = get_logger(__name__)


def enrich(ip: str) -> Dict[str, Any]:
    """Enrich an IP address with ASN/org/country data.

    Returns a dict with keys ``asn``, ``asn_org``, ``country``,
    ``hosting_provider``, ``reverse_dns``. Any field that cannot be
    resolved is ``None``.
    """
    out: Dict[str, Any] = {
        "address": ip,
        "asn": None,
        "asn_org": None,
        "country": None,
        "hosting_provider": None,
        "reverse_dns": _reverse_dns(ip),
    }
    try:
        version = ipaddress.ip_address(ip).version
    except ValueError:
        logger.warning("Invalid IP for ASN enrichment: %s", ip)
        return out

    try:
        if version == 4:
            asn_query = _build_ipv4_query(ip)
        else:
            asn_query = _build_ipv6_query(ip)

        txt_records = _resolve_txt(asn_query)
        if not txt_records:
            return out

        # Format: "ASNN | prefix | country | registry | date"
        first = txt_records[0].strip('"').strip()
        parts = [p.strip() for p in first.split("|")]
        if len(parts) >= 3:
            asn_raw = parts[0]
            out["country"] = parts[2] or None
            if asn_raw and asn_raw.startswith("AS"):
                asn_num = asn_raw[2:]
                out["asn"] = asn_raw
                # Lookup org name
                org = _lookup_org(asn_num)
                out["asn_org"] = org
                out["hosting_provider"] = _classify_provider(org) if org else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("ASN lookup failed for %s: %s", ip, exc)

    return out


# --------------------------------------------------------------------------- helpers

def _resolve_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=10)
        return [r.to_text() for r in answers]
    except Exception:
        return []


def _build_ipv4_query(ip: str) -> str:
    octets = ip.split(".")
    reversed_octets = ".".join(reversed(octets))
    return f"{reversed_octets}.origin.asn.cymru.com"


def _build_ipv6_query(ip: str) -> str:
    # Build the nibble-reversed form for IPv6 (RFC 2671 style)
    addr = ipaddress.IPv6Address(ip)
    hex_str = addr.exploded.replace(":", "")
    reversed_nibbles = ".".join(reversed(hex_str))
    return f"{reversed_nibbles}.origin6.asn.cymru.com"


def _lookup_org(asn_num: str) -> Optional[str]:
    """Resolve ``AS<asn>.asn.cymru.com`` TXT for organization name."""
    txt = _resolve_txt(f"AS{asn_num}.asn.cymru.com")
    if not txt:
        return None
    first = txt[0].strip('"').strip()
    # Format: "AS | country | registry | allocated | org-name"
    parts = [p.strip() for p in first.split("|")]
    if len(parts) >= 5:
        return parts[4] or None
    return None


def _classify_provider(org_name: str) -> Optional[str]:
    """Heuristic mapping from ASN org name to hosting provider bucket."""
    org_lower = org_name.lower()
    if "amazon" in org_lower or "aws" in org_lower:
        return "AWS"
    if "microsoft" in org_lower or "azure" in org_lower:
        return "Azure"
    if "google" in org_lower:
        return "GCP"
    if "cloudflare" in org_lower:
        return "Cloudflare"
    if "digitalocean" in org_lower:
        return "DigitalOcean"
    if "fastly" in org_lower:
        return "Fastly"
    if "akamai" in org_lower:
        return "Akamai"
    if "vercel" in org_lower:
        return "Vercel"
    if "netlify" in org_lower:
        return "Netlify"
    if "github" in org_lower:
        return "GitHub Pages"
    return None


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        import socket
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None
    except Exception:
        return None
