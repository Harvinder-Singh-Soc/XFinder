"""httpx (projectdiscovery) wrapper – live HTTP detection + fingerprinting.

IMPORTANT: there are TWO different tools called "httpx":

1. **Python httpx CLI** (from the `httpx` PyPI package) — installed in
   Python virtualenvs. Accepts options like `--json`, `--no-verify`.
2. **ProjectDiscovery httpx** (Go binary) — the one we actually want.
   Accepts options like `-silent`, `-json`, `-status-code`, `-tech-detect`.

Both binaries are often named `httpx` and live on $PATH. We must use the
PD version, not the Python one. This module resolves the binary path
explicitly to avoid the conflict.
"""

from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List, Optional

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess, safe_jsonl_loads


def _find_pd_httpx() -> Optional[str]:
    """Find the ProjectDiscovery httpx binary.

    Returns the absolute path, or None if not found. We try in order:

    1. ``XFINDER_HTTPX_BIN`` env var (explicit override)
    2. ``$GOPATH/bin/httpx`` (typical Go install location)
    3. ``$HOME/go/bin/httpx``
    4. Any ``httpx`` on $PATH whose ``-version`` output mentions
       "projectdiscovery" or "Current Version: v"
    """
    # 1. Explicit override
    explicit = os.environ.get("XFINDER_HTTPX_BIN")
    if explicit and os.path.exists(explicit) and os.access(explicit, os.X_OK):
        return explicit

    # 2/3. Common Go install locations
    gopath = os.environ.get("GOPATH") or os.path.join(os.path.expanduser("~"), "go")
    candidates = [
        os.path.join(gopath, "bin", "httpx"),
        os.path.join(os.path.expanduser("~"), "go", "bin", "httpx"),
        "/usr/local/go/bin/httpx",
        "/opt/go/bin/httpx",
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c

    # 4. Walk $PATH and probe each httpx for PD signature
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for d in path_dirs:
        candidate = os.path.join(d, "httpx")
        if not (os.path.exists(candidate) and os.access(candidate, os.X_OK)):
            continue
        # Probe: PD httpx prints "projectdiscovery.io" or "Current Version: v"
        # Python httpx prints "Usage: httpx [OPTIONS] URL"
        probe = run_subprocess([candidate, "-version"], timeout=5, retries=1)
        out = (probe.stdout or "") + (probe.stderr or "")
        if "projectdiscovery" in out.lower() or "current version" in out.lower():
            return candidate

    # Last resort: return whatever `which httpx` finds (may be the wrong one)
    return shutil.which("httpx")


# Cache the resolved binary path so we don't re-probe on every scan.
_PD_HTTPX_BIN: Optional[str] = None


def _get_pd_httpx() -> Optional[str]:
    global _PD_HTTPX_BIN
    if _PD_HTTPX_BIN is None:
        _PD_HTTPX_BIN = _find_pd_httpx()
    return _PD_HTTPX_BIN


class HttpxScanner(BaseScanner):
    name = "httpx"
    description = "Live HTTP detection, status, title, server, technologies"
    # We don't list "httpx" in required_tools because that would falsely
    # report the Python httpx as satisfying the requirement. We check
    # for the PD version explicitly in execute().
    required_tools: List[str] = []

    def run(self) -> ScanResult:
        binary = _get_pd_httpx()
        if binary is None:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error=("ProjectDiscovery httpx not found. The 'httpx' on your "
                       "PATH may be the Python httpx CLI. Install PD httpx: "
                       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            )

        # Resolve subdomains from cache or fall back to ctx.subdomains
        hosts: List[str] = self.ctx.cache.get("resolved_subdomains") or self.ctx.subdomains or []
        if not hosts:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="No hosts to probe (run dnsx first)",
            )

        # CAP: For large targets like google.com (271+ subdomains), cap httpx
        # to first 50 hosts to keep scan time reasonable.
        MAX_HTTPX_HOSTS = 50
        if len(hosts) > MAX_HTTPX_HOSTS:
            self.log.info("Capping httpx to first %d hosts (out of %d)",
                          MAX_HTTPX_HOSTS, len(hosts))
            hosts = hosts[:MAX_HTTPX_HOSTS]

        stdin = "\n".join(hosts)
        # Build the httpx command. We use only widely-supported flags.
        cmd = [
            binary,
            "-silent",
            "-json",
            "-status-code", "-title", "-server",
            "-content-length",
            "-tech-detect", "-ip", "-cname",
            "-timeout", str(settings.httpx_timeout),
            "-threads", str(min(self.ctx.threads, 50)),
            "-no-color",
            "-follow-redirects",
        ]
        self.log.info("Running httpx on %d hosts (per-host timeout=%ss, threads=%d) [%s]",
                      len(hosts), settings.httpx_timeout, min(self.ctx.threads, 50), binary)
        self.log.debug("httpx command: %s", " ".join(cmd))
        # Total timeout: generous to handle large host counts (google.com has 271+)
        # Formula: per-host * (hosts / threads) + 120s buffer
        # For 271 hosts / 20 threads → 10 * 14 + 120 = 260s
        # For 50 hosts / 20 threads → 10 * 3 + 120 = 150s
        total_timeout = settings.httpx_timeout * (len(hosts) // max(1, self.ctx.threads) + 2) + 120
        res = run_subprocess(
            cmd, timeout=total_timeout, retries=1, input_text=stdin
        )
        if res.timed_out:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="httpx timed out",
            )

        # Surface httpx stderr if stdout is empty
        if res.stderr and not res.stdout.strip():
            stderr_preview = res.stderr.strip()[:500]
            self.log.error("httpx produced no output. stderr: %s", stderr_preview)
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error=f"httpx produced no output. stderr: {stderr_preview}",
                raw_output=res.stdout,
            )

        rows = safe_jsonl_loads(res.stdout)
        live: List[Dict[str, Any]] = []
        for row in rows:
            if row.get("failed") is True:
                continue
            url = (row.get("url")
                   or row.get("input")
                   or row.get("matched-at")
                   or "")
            if not url:
                continue
            host = (row.get("host") or row.get("input") or "")
            if not host:
                from urllib.parse import urlparse
                try:
                    host = urlparse(url).hostname or ""
                except Exception:
                    host = ""

            # Collect all IPs (both IPv4 and IPv6)
            ips: List[str] = []
            for field in ("a", "aaaa"):
                val = row.get(field)
                if isinstance(val, list):
                    ips.extend(val)
                elif isinstance(val, str) and val:
                    ips.append(val)
            host_ip = row.get("host_ip")
            if host_ip and host_ip not in ips:
                ips.append(host_ip)

            live.append({
                "url": url,
                "host": host,
                "final_url": row.get("final_url") or row.get("final-url") or url,
                "status_code": row.get("status_code") or row.get("status"),
                "title": row.get("title"),
                "server_header": row.get("webserver") or row.get("server"),
                "content_length": (row.get("content_length")
                                   or row.get("length")
                                   or row.get("bytes")),
                "response_time_ms": self._parse_rt(row.get("time") or row.get("response_time")),
                "scheme": row.get("scheme"),
                "webserver": row.get("webserver"),
                "technologies": row.get("tech") or row.get("technologies") or [],
                "ips": ips,
                "cnames": row.get("cname") or [],
            })

        # Cache live hosts for downstream scanners (naabu, katana, nuclei)
        self.ctx.live_hosts = [r["host"] for r in live if r.get("host")]
        self.ctx.cache["http_results"] = live

        self.log.info("httpx found %d live hosts out of %d probed",
                      len(live), len(hosts))
        if not live and hosts:
            self.log.warning(
                "httpx returned 0 live hosts despite %d input hosts. "
                "Stdout was %d chars, stderr was %d chars. "
                "Try running manually: echo '%s' | %s",
                len(hosts),
                len(res.stdout or ""),
                len(res.stderr or ""),
                hosts[0] if hosts else "",
                " ".join(cmd),
            )

        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={"hosts": live, "count": len(live)},
            raw_output=res.stdout,
        )

    @staticmethod
    def _parse_rt(rt) -> int | None:
        """Parse httpx's response time field ('4.66s' or '234ms')."""
        if rt is None:
            return None
        s = str(rt).strip().lower()
        try:
            if s.endswith("ms"):
                return int(float(s[:-2]))
            if s.endswith("s"):
                return int(float(s[:-1]) * 1000)
            return int(float(s) * 1000)
        except (ValueError, TypeError):
            return None
