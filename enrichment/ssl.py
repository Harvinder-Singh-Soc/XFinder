"""SSL certificate metadata extraction.

Connects to the host on port 443, retrieves the server certificate, and
extracts:

* Issuer Common Name
* Subject Common Name
* Valid from / to dates
* Serial number
* Signature algorithm
* SANs (Subject Alternative Names)

Uses ``ssl`` from the standard library plus ``pyOpenSSL`` for richer
parsing. Falls back gracefully when pyOpenSSL is unavailable.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10


def enrich(host: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Retrieve SSL certificate metadata for ``host:port``.

    Returns a dict with the certificate fields, or an ``error`` key on
    failure. Never raises.
    """
    result: Dict[str, Any] = {"host": host, "port": port}
    try:
        cert_dict = _fetch_cert(host, port, timeout)
        if cert_dict is None:
            result["error"] = "No certificate returned"
            return result

        result.update({
            "issuer_cn": _extract_cn(cert_dict.get("issuer", [])),
            "subject_cn": _extract_cn(cert_dict.get("subject", [])),
            "valid_from": cert_dict.get("notBefore"),
            "valid_to": cert_dict.get("notAfter"),
            "serial_number": cert_dict.get("serialNumber"),
            "signature_algorithm": cert_dict.get("signatureAlgorithm"),
            "version": cert_dict.get("version"),
            "sans": _extract_sans(cert_dict),
        })

        # Self-signed detection
        result["is_self_signed"] = (
            result["issuer_cn"] is not None
            and result["issuer_cn"] == result["subject_cn"]
        )

        # Expiry check
        result["is_expired"] = _is_expired(cert_dict.get("notAfter"))
    except ssl.SSLError as exc:
        result["error"] = f"SSL error: {exc}"
        logger.debug("SSL error for %s: %s", host, exc)
    except socket.timeout:
        result["error"] = f"Connection timed out after {timeout}s"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Unexpected error: {exc}"
        logger.debug("SSL enrich failed for %s: %s", host, exc)
    return result


# --------------------------------------------------------------------------- helpers

def _fetch_cert(host: str, port: int, timeout: int) -> Optional[dict]:
    """Connect to ``host:port`` and return the parsed certificate dict."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der:
                # Try pyOpenSSL for richer parsing
                try:
                    from OpenSSL import crypto
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)
                    return _pyopenssl_to_dict(x509)
                except ImportError:
                    pass
            # Fall back to stdlib (limited)
            cert_dict = ssock.getpeercert()
            return cert_dict


def _pyopenssl_to_dict(x509) -> dict:
    """Convert a pyOpenSSL X509 object to a dict similar to stdlib's."""
    from OpenSSL import crypto
    issuer = [(n.decode() if isinstance(n, bytes) else n, v.decode() if isinstance(v, bytes) else v)
              for n, v in x509.get_issuer().get_components()]
    subject = [(n.decode() if isinstance(n, bytes) else n, v.decode() if isinstance(v, bytes) else v)
               for n, v in x509.get_subject().get_components()]

    # SANs
    sans: List[str] = []
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        if ext.get_short_name() == b"subjectAltName":
            sans = [s.strip() for s in str(ext).split(",")]
            sans = [s.replace("DNS:", "").strip() for s in sans if s.startswith("DNS:")]

    return {
        "issuer": issuer,
        "subject": subject,
        "notBefore": x509.get_notBefore().decode("ascii") if isinstance(x509.get_notBefore(), bytes) else x509.get_notBefore(),
        "notAfter": x509.get_notAfter().decode("ascii") if isinstance(x509.get_notAfter(), bytes) else x509.get_notAfter(),
        "serialNumber": str(x509.get_serial_number()),
        "signatureAlgorithm": x509.get_signature_algorithm().decode("ascii")
                              if isinstance(x509.get_signature_algorithm(), bytes)
                              else x509.get_signature_algorithm(),
        "version": x509.get_version(),
        "sans": sans,
    }


def _extract_cn(name_field) -> Optional[str]:
    """Extract Common Name from an issuer/subject field.

    Handles both stdlib format ``[('CN', 'example.com'), ...]`` and pyOpenSSL
    format ``[(b'CN', b'example.com'), ...]``.
    """
    if not name_field:
        return None
    for item in name_field:
        try:
            key, value = item
            if isinstance(key, bytes):
                key = key.decode("ascii", errors="ignore")
            if isinstance(value, bytes):
                value = value.decode("ascii", errors="ignore")
            if key == "CN":
                return value
        except (ValueError, TypeError):
            continue
    return None


def _extract_sans(cert_dict: dict) -> List[str]:
    sans = cert_dict.get("sans")
    if isinstance(sans, list):
        return sans
    # stdlib subjectAltName format: tuple of (type, value)
    san_field = cert_dict.get("subjectAltName")
    if isinstance(san_field, tuple):
        return [v for t, v in san_field if t == "DNS"]
    return []


def _is_expired(not_after: Optional[str]) -> Optional[bool]:
    """Return True if *not_after* is in the past, None if unparseable."""
    if not not_after:
        return None
    try:
        # pyOpenSSL format: "YYYYMMDDHHMMSSZ"
        if not_after.isdigit() and len(not_after) == 15:
            dt = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
        else:
            # stdlib format: "Jun 28 23:59:59 2026 GMT"
            dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return dt < datetime.utcnow()
    except (ValueError, TypeError):
        return None
