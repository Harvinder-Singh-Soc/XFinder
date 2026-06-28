"""Cloud / CDN / WAF provider detection.

Detection strategy (in order of reliability):

1. CNAME chain – if it ends with a known cloud domain (e.g. ``*.cloudfront.net``),
   we are confident the asset is hosted on that provider.
2. HTTP ``Server`` header – often reveals nginx/apache/CDN-specific strings.
3. Response headers – Cloudflare/Fastly/Akamai set distinctive headers.

This module is intentionally conservative: we only set ``provider`` when we
have concrete evidence, otherwise we leave it ``None`` to avoid false
positives.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# --------------------------------------------------------------------------- provider fingerprints

# CNAME suffix -> provider name. Checked in order; first match wins.
CNAME_PROVIDERS: Dict[str, str] = {
    # AWS
    "cloudfront.net": "AWS CloudFront",
    "elb.amazonaws.com": "AWS ELB",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3",
    "awsstatic.com": "AWS",
    # Azure
    "azureedge.net": "Azure CDN",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure",
    "blob.core.windows.net": "Azure Blob",
    # GCP
    "c.storage.googleapis.com": "GCP Storage",
    "storage.googleapis.com": "GCP Storage",
    "appspot.com": "GCP App Engine",
    "cloudrun.dev": "GCP Cloud Run",
    # CDNs
    "cdn.cloudflare.net": "Cloudflare",
    "cloudflare.com": "Cloudflare",
    "fastly.net": "Fastly",
    "edgesuite.net": "Akamai",
    "akamaized.net": "Akamai",
    "akamaihd.net": "Akamai",
    # PaaS / static
    "netlify.app": "Netlify",
    "netlifyglobalcdn.com": "Netlify",
    "vercel.app": "Vercel",
    "zeit.co": "Vercel",
    "github.io": "GitHub Pages",
    "pages.dev": "Cloudflare Pages",
    "herokuapp.com": "Heroku",
    "herokuapp.com.": "Heroku",
    "digitaloceanspaces.com": "DigitalOcean",
    # Common hosting providers
    "kinsta.com": "Kinsta",
    "kinsta.cloud": "Kinsta",
    "wpengine.com": "WP Engine",
}

# Server-header patterns -> (provider, cdn, waf)
SERVER_PATTERNS: List[tuple] = [
    (re.compile(r"cloudflare", re.I), "Cloudflare", "Cloudflare", "Cloudflare"),
    (re.compile(r"fastly", re.I), "Fastly", "Fastly", None),
    (re.compile(r"akamai", re.I), "Akamai", "Akamai", None),
    (re.compile(r"amazonelb", re.I), "AWS ELB", None, None),
    (re.compile(r"aws", re.I), "AWS", None, None),
    (re.compile(r"azure", re.I), "Azure", None, None),
    (re.compile(r"netlify", re.I), "Netlify", None, None),
    (re.compile(r"vercel", re.I), "Vercel", None, None),
    (re.compile(r"github", re.I), "GitHub Pages", None, None),
    (re.compile(r"digitalocean", re.I), "DigitalOcean", None, None),
]

# Distinctive response headers -> provider
HEADER_PROVIDERS: Dict[str, str] = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-amz-cf-id": "AWS CloudFront",
    "x-azure-ref": "Azure",
    "x-vercel-id": "Vercel",
    "x-netlify": "Netlify",
    "x-github-request": "GitHub Pages",
    "server: digitalocean": "DigitalOcean",
}


# --------------------------------------------------------------------------- public API

def detect(
    host: str,
    cnames: Optional[List[str]] = None,
    server_header: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Detect cloud / CDN / WAF provider for a host.

    Parameters
    ----------
    host:
        The hostname (used only for logging).
    cnames:
        CNAME chain values from DNS.
    server_header:
        HTTP ``Server`` header value.
    headers:
        Full HTTP response headers (lowercased keys).

    Returns
    -------
    dict
        Keys: ``provider``, ``cdn``, ``waf``, ``is_cloud_hosted``, ``evidence``.
    """
    evidence_parts: List[str] = []
    provider: Optional[str] = None
    cdn: Optional[str] = None
    waf: Optional[str] = None

    # 1. CNAME chain
    if cnames:
        for cname in cnames:
            cl = cname.lower().rstrip(".")
            for suffix, prov in CNAME_PROVIDERS.items():
                if cl.endswith(suffix) or suffix in cl:
                    provider = prov
                    if prov in {"Cloudflare", "AWS CloudFront", "Fastly", "Akamai",
                                "Azure CDN", "Cloudflare Pages"}:
                        cdn = prov
                    evidence_parts.append(f"CNAME:{cname}")
                    break
            if provider:
                break

    # 2. Server header
    if not provider and server_header:
        for pat, prov, cdn_val, waf_val in SERVER_PATTERNS:
            if pat.search(server_header):
                provider = prov
                cdn = cdn_val
                waf = waf_val
                evidence_parts.append(f"Server:{server_header}")
                break

    # 3. Response headers
    if headers:
        h_lower = {k.lower(): v for k, v in headers.items()}
        for h_name, prov in HEADER_PROVIDERS.items():
            # Allow "key: value" form too (for safety)
            if ":" in h_name:
                key, val = h_name.split(":", 1)
                if key.strip() in h_lower and val.strip().lower() in str(h_lower[key]).lower():
                    if not provider:
                        provider = prov
                    evidence_parts.append(f"Header:{h_name}")
            else:
                if h_name in h_lower:
                    if not provider:
                        provider = prov
                    if prov in {"Cloudflare", "Fastly", "Akamai"}:
                        if not cdn:
                            cdn = prov
                        if prov == "Cloudflare" and not waf:
                            waf = prov
                    evidence_parts.append(f"Header:{h_name}")

    result: Dict[str, Any] = {
        "provider": provider,
        "cdn": cdn,
        "waf": waf,
        "is_cloud_hosted": provider is not None,
        "evidence": "; ".join(evidence_parts) if evidence_parts else None,
    }
    if provider:
        logger.debug("Cloud detected for %s: %s", host, result)
    return result
