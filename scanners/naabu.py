"""Naabu wrapper – fast TCP port discovery on live hosts only.

Optimizations:
* ``-ec`` (exclude-cdn): skip full port scans for CDN/WAF-protected hosts
  (only scan 80/443). This is critical for sites like google.com where 50+
  subdomains resolve to a handful of CDN IPs.
* Uses CONNECT scan (no root needed).
* Short per-host timeout to avoid hanging on filtered IPs.
"""

from __future__ import annotations

from typing import Any, Dict, List

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess, safe_jsonl_loads


class NaabuScanner(BaseScanner):
    name = "naabu"
    description = "Fast port discovery (run only on hosts confirmed live by httpx)"
    required_tools = ["naabu"]

    #: Common ports to scan (no T: prefix — naabu v2.3+ doesn't accept it).
    DEFAULT_PORTS = ("21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,"
                     "587,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,"
                     "5984,6379,6443,7001,8000,8009,8080,8081,8443,8888,9000,"
                     "9090,9200,9300,11211,27017,50000")

    def run(self) -> ScanResult:
        hosts: List[str] = self.ctx.live_hosts or []
        if not hosts:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="No live hosts (run httpx first)",
            )
        # naabu can be slow on IPv6 - keep only hostnames and IPv4 addresses
        # Hostnames are fine because naabu will resolve them to IPv4
        filtered_hosts = []
        for h in hosts:
            # If it looks like an IPv6 address (contains multiple colons), skip it
            if h.count(":") > 1:
                continue
            filtered_hosts.append(h)
        if len(filtered_hosts) < len(hosts):
            self.log.info("Filtered %d IPv6 addresses from naabu input",
                          len(hosts) - len(filtered_hosts))
        hosts = filtered_hosts

        # CAP: For large targets like google.com (90+ live hosts), cap naabu
        # to first 20 hosts to keep scan time reasonable.
        MAX_NAABU_HOSTS = 20
        if len(hosts) > MAX_NAABU_HOSTS:
            self.log.info("Capping naabu to first %d live hosts (out of %d)",
                          MAX_NAABU_HOSTS, len(hosts))
            hosts = hosts[:MAX_NAABU_HOSTS]

        if not hosts:
            return ScanResult(
                scanner=self.name, success=True, duration_seconds=0.0,
                data={"open_ports": [], "ip_to_ports": {}, "host_count": 0, "port_count": 0},
            )
        stdin = "\n".join(hosts)
        # Build naabu command. -ec skips full port scan for CDN/WAF hosts
        # (only scans 80/443 for them) — critical for cloud-hosted sites.
        cmd = [
            "naabu",
            "-silent",
            "-json",
            "-port", self.DEFAULT_PORTS,
            "-timeout", str(settings.naabu_timeout),
            "-rate", str(self.ctx.rate),
            "-retries", "1",
            "-verify",
            "-scan-type", "c",       # CONNECT scan (no root needed)
            "-ec",                   # exclude CDN (skip full scan for CDN IPs)
        ]
        self.log.info("Running naabu on %d live hosts (per-host timeout=%ss, ports=%d, exclude-cdn=True)",
                      len(hosts), settings.naabu_timeout, len(self.DEFAULT_PORTS.split(",")))
        self.log.debug("naabu command: %s", " ".join(cmd))
        # Total timeout: per-host (10s) * batches + 120s buffer
        # For 50 hosts / 20 threads = 3 batches → 30s + 120s = 150s max
        total_timeout = settings.naabu_timeout * (
            len(hosts) // max(1, self.ctx.threads) + 3
        ) + 120
        res = run_subprocess(
            cmd, timeout=total_timeout, retries=1, input_text=stdin
        )
        if res.timed_out:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error=f"naabu timed out after {total_timeout}s",
            )

        # Surface naabu stderr if stdout is empty
        if res.stderr and not res.stdout.strip():
            stderr_preview = res.stderr.strip()[:500]
            self.log.error("naabu produced no output. stderr: %s", stderr_preview)
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error=f"naabu produced no output. stderr: {stderr_preview}",
                raw_output=res.stdout,
            )

        rows = safe_jsonl_loads(res.stdout)
        by_ip: Dict[str, List[int]] = {}
        by_host: List[Dict[str, Any]] = []
        seen_pairs: set = set()
        for row in rows:
            ip = row.get("ip") or row.get("host")
            port = row.get("port")
            if not ip or port is None:
                continue
            host = row.get("host") or row.get("input") or ip
            key = (host, int(port))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            by_ip.setdefault(ip, []).append(int(port))
            by_host.append({
                "host": host,
                "ip": ip,
                "port": int(port),
                "protocol": row.get("protocol", "tcp"),
            })

        # Cache for nmap
        self.ctx.ports = by_ip
        self.ctx.cache["naabu_results"] = by_host

        self.log.info("naabu found %d open ports across %d hosts (unique IPs: %d)",
                      len(by_host), len({r["host"] for r in by_host}), len(by_ip))
        if not by_host:
            self.log.warning(
                "naabu returned 0 open ports despite %d live hosts. "
                "Hosts may be firewalled, behind CDN, or only expose 80/443 "
                "(which httpx already confirmed live).",
                len(hosts),
            )

        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={
                "open_ports": by_host,
                "ip_to_ports": by_ip,
                "host_count": len({r["host"] for r in by_host}),
                "port_count": len(by_host),
            },
            raw_output=res.stdout,
        )
