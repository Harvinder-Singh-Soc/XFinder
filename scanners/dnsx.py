"""dnsx wrapper – DNS resolution for A/AAAA/CNAME/MX/TXT/NS/SOA records.

Tested against dnsx v1.2.2+. dnsx emits ONE JSONL line per host with all
record types bundled as arrays (e.g. {"a": [...], "aaaa": [...], "soa": [...]}).
We expand each field into individual normalized records.
"""

from __future__ import annotations

from typing import Any, Dict, List

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess, safe_jsonl_loads


class DnsxScanner(BaseScanner):
    name = "dnsx"
    description = "DNS resolution (A, AAAA, CNAME, MX, TXT, NS, SOA)"
    required_tools = ["dnsx"]

    #: Map dnsx JSON field name -> DNS record type.
    #: dnsx bundles records as arrays under these keys (e.g. {"a": ["1.2.3.4"]}).
    FIELD_TO_TYPE = {
        "a":     "A",
        "aaaa":  "AAAA",
        "cname": "CNAME",
        "mx":    "MX",
        "txt":   "TXT",
        "ns":    "NS",
        "soa":   "SOA",
    }

    def run(self) -> ScanResult:
        if not self.ctx.subdomains:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="No subdomains to resolve (run subfinder first)",
            )
        # dnsx reads hosts from stdin when no -d / -l flag is given.
        stdin = "\n".join(self.ctx.subdomains)
        cmd = [
            "dnsx",
            "-silent",
            "-json",
            "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns", "-soa",
            "-t", str(self.ctx.threads),
            "-timeout", str(settings.dnsx_timeout),
            "-retry", "1",
        ]
        self.log.info("Running dnsx on %d hosts (per-query timeout=%ss, threads=%d)",
                      len(self.ctx.subdomains), settings.dnsx_timeout, self.ctx.threads)
        self.log.debug("dnsx command: %s", " ".join(cmd))
        # Total timeout = per-query (10s) * (13 hosts / 20 threads + 2) + 60s buffer
        total_timeout = settings.dnsx_timeout * (
            len(self.ctx.subdomains) // max(1, self.ctx.threads) + 2
        ) + 60
        res = run_subprocess(cmd, timeout=total_timeout, retries=1, input_text=stdin)
        if res.timed_out:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="dnsx timed out",
            )

        # Surface dnsx stderr if stdout is empty
        if res.stderr and not res.stdout.strip():
            stderr_preview = res.stderr.strip()[:500]
            self.log.error("dnsx produced no output. stderr: %s", stderr_preview)
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error=f"dnsx produced no output. stderr: {stderr_preview}",
                raw_output=res.stdout,
            )

        records = safe_jsonl_loads(res.stdout)
        normalized: List[Dict[str, Any]] = []
        resolved_hosts: List[str] = []

        for rec in records:
            host = (rec.get("host") or rec.get("input") or "").strip().lower()
            if not host:
                continue
            resolved_hosts.append(host)
            ttl = rec.get("ttl")

            # dnsx bundles all record types in a single JSON line.
            # Each field (a, aaaaa, cname, mx, txt, ns, soa) is either an
            # array or a single value. Expand into individual records.
            for field, rtype in self.FIELD_TO_TYPE.items():
                value = rec.get(field)
                if value is None:
                    continue
                if isinstance(value, list):
                    for v in value:
                        normalized.append(self._normalize_record(host, rtype, v, ttl))
                elif isinstance(value, dict):
                    # SOA records often come as dicts
                    normalized.append(self._normalize_record(host, rtype, value, ttl))
                elif value:
                    normalized.append(self._normalize_record(host, rtype, value, ttl))

        self.log.info(
            "dnsx resolved %d/%d hosts, %d total records",
            len(set(resolved_hosts)), len(self.ctx.subdomains), len(normalized),
        )
        if not resolved_hosts:
            self.log.warning(
                "dnsx resolved 0 hosts out of %d. Check resolver connectivity. "
                "Stdout was %d chars, stderr was %d chars. "
                "Try running manually: echo '%s' | %s",
                len(self.ctx.subdomains),
                len(res.stdout or ""),
                len(res.stderr or ""),
                self.ctx.subdomains[0] if self.ctx.subdomains else "",
                " ".join(cmd),
            )

        # Cache resolved subdomains for downstream scanners
        self.ctx.cache["dns_records"] = normalized
        self.ctx.cache["resolved_subdomains"] = sorted(set(resolved_hosts))

        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={
                "records": normalized,
                "resolved_count": len(set(resolved_hosts)),
                "record_count": len(normalized),
            },
            raw_output=res.stdout,
        )

    @staticmethod
    def _normalize_record(host: str, rtype: str, value: Any, ttl: Any) -> Dict[str, Any]:
        """Convert a dnsx field value into a flat record dict."""
        # Handle SOA dict form: {"name": ..., "ns": ..., "mailbox": ..., ...}
        if isinstance(value, dict):
            parts = []
            for k in ("ns", "mailbox", "serial", "refresh", "retry", "expire", "minttl"):
                if k in value:
                    parts.append(f"{k}={value[k]}")
            value_str = " ".join(parts) if parts else str(value)
        else:
            value_str = str(value)
        return {
            "host": host,
            "type": rtype,
            "value": value_str,
            "ttl": ttl,
        }
