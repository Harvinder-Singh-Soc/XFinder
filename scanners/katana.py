"""Katana wrapper – web crawling & API endpoint discovery.

Tested against katana v1.6.1+. Flag changes vs older versions:

* ``-no-sandbox`` → ``-nos``
* ``-jc`` is now ``-js-crawl`` (JavaScript crawl), NOT JSON output
* ``-j`` or ``-jsonl`` is the JSON output flag
* Headless mode requires ``-hl`` (not implicit) when ``-nos`` is used
* ``-sc`` (system-chrome) prefers locally-installed Chrome over downloading

If Chrome/Chromium is not installed locally, katana will attempt to download
it on first run. Set ``KATANA_SKIP_DOWNLOAD=1`` in the environment to skip
this and fail fast instead.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess, safe_jsonl_loads


class KatanaScanner(BaseScanner):
    name = "katana"
    description = "Web crawling & API endpoint discovery"
    required_tools = ["katana"]

    def run(self) -> ScanResult:
        live_hosts: List[str] = self.ctx.live_hosts or []
        if not live_hosts:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="No live hosts to crawl (run httpx first)",
            )

        # CAP the number of hosts we crawl to avoid extremely long scans
        # and OOM kills from Chrome. Chrome uses ~200MB per tab, so 5 hosts
        # = ~1GB just for Chrome.
        MAX_KATANA_HOSTS = 5
        if len(live_hosts) > MAX_KATANA_HOSTS:
            self.log.info("Capping katana to first %d live hosts (out of %d)",
                          MAX_KATANA_HOSTS, len(live_hosts))
            live_hosts = live_hosts[:MAX_KATANA_HOSTS]

        all_endpoints: List[Dict[str, Any]] = []
        failed_hosts: List[str] = []
        for host in live_hosts:
            url = host if host.startswith("http") else f"https://{host}"
            cmd = [
                "katana",
                "-u", url,
                "-silent",
                "-j",                  # JSONL output (was -jc which is now js-crawl)
                "-d", "2",             # depth
                "-c", str(min(self.ctx.threads, 20)),
                "-timeout", "5",       # per-request timeout (short = faster)
                "-retry", "1",
                "-hl",                 # headless mode (required with -nos)
                "-nos",                # no-sandbox (was -no-sandbox)
                "-sc",                 # use system chrome (avoid download)
                "-s", "breadth-first", # breadth-first is faster for shallow scans
                "-ct", str(settings.katana_timeout),  # crawl duration (overall cap)
            ]
            self.log.info("Running katana on %s (timeout=%ss)", url, settings.katana_timeout)
            self.log.debug("katana command: %s", " ".join(cmd))
            # Per-host timeout = katana_timeout + 60s buffer for browser startup
            per_host_timeout = settings.katana_timeout + 60
            res = run_subprocess(
                cmd, timeout=per_host_timeout, retries=1
            )
            if res.timed_out:
                self.log.warning("katana timed out on %s after %ss",
                                 url, per_host_timeout)
                failed_hosts.append(host)
                continue
            if not res.ok:
                stderr_prev = (res.stderr or "")[:200]
                self.log.warning("katana failed for %s: %s", url, stderr_prev)
                failed_hosts.append(host)
                continue
            rows = safe_jsonl_loads(res.stdout)
            for row in rows:
                endpoint_url = row.get("request", {}).get("endpoint") or row.get("url")
                if not endpoint_url:
                    continue
                method = row.get("request", {}).get("method", "GET")
                body = row.get("request", {}).get("body")
                tag = row.get("tag") or row.get("source")
                all_endpoints.append({
                    "source_host": host,
                    "method": method,
                    "url": endpoint_url,
                    "body": body,
                    "tag": tag,
                })

        # Dedupe endpoints
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for ep in all_endpoints:
            key = (ep["source_host"], ep["method"], ep["url"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(ep)

        self.ctx.cache["katana_results"] = deduped
        self.log.info("katana found %d unique endpoints across %d hosts (%d hosts failed)",
                      len(deduped), len({e["source_host"] for e in deduped}),
                      len(failed_hosts))

        if not deduped:
            self.log.warning(
                "katana returned 0 endpoints. This usually means Chrome/Chromium "
                "is not installed. Install with: sudo apt-get install -y chromium "
                "or set KATANA_SKIP_DOWNLOAD=1 and use -system-chrome."
            )

        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={
                "endpoints": deduped,
                "host_count": len({e["source_host"] for e in deduped}),
                "endpoint_count": len(deduped),
                "failed_hosts": failed_hosts,
            },
        )
