"""Validation helpers for user-supplied inputs (domains, IPs, etc.)."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# RFC-1035-ish domain regex. Allows labels of 1-63 chars, total 1-253.
# Does NOT allow leading/trailing hyphens on labels.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+"
    r"[A-Za-z]{2,63}$"
)


def is_valid_domain(domain: str) -> bool:
    """Return True if *domain* is a syntactically valid DNS name.

    Examples::

        >>> is_valid_domain("example.com")
        True
        >>> is_valid_domain("sub.example.co.uk")
        True
        >>> is_valid_domain("-bad.example.com")
        False
        >>> is_valid_domain("not_a_domain")
        False
    """
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip().lower().rstrip(".")
    if len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain))


def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def is_valid_url(url: str) -> bool:
    """Return True if *url* parses to an http(s) URL with a netloc."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def normalize_domain(domain: str) -> str:
    """Normalize a domain: strip whitespace, lowercase, strip trailing dot."""
    return domain.strip().lower().rstrip(".")


def extract_hostname_from_url(url: str) -> str | None:
    """Extract the hostname (without port) from a URL.

    Returns ``None`` if the URL is malformed or has no netloc.
    """
    try:
        parsed = urlparse(url.strip())
        return parsed.hostname
    except Exception:
        return None
