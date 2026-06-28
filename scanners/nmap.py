"""Nmap wrapper – service/version detection, scoped to Naabu-discovered ports only.

Optimizations:
* Deduplicates IPs (multiple subdomains often resolve to the same IP —
  we only scan each IP once with the union of its ports).
* Uses ``--max-parallelism`` and ``-T4`` for faster scans.
* Optional OS detection (requires root) — disabled by default.

NOTE: We intentionally DO NOT use ``-O`` (OS detection) because it requires
root privileges. Set ``XFINDER_NMAP_OS_DETECT=1`` and run as root to enable.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Set

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import ensure_dir, run_subprocess


class NmapScanner(BaseScanner):
    name = "nmap"
    description = "Service / version detection (only on Naabu-discovered ports)"
    required_tools = ["nmap"]

    def run(self) -> ScanResult:
        ip_to_ports: Dict[str, List[int]] = self.ctx.ports or {}
        if not ip_to_ports:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="No ports discovered (run naabu first)",
            )

        # Write XML output to the scan output dir so we can re-parse later.
        out_xml = ensure_dir(self.ctx.output_dir) / "nmap_scan.xml"

        # OPTIMIZATION: Many subdomains resolve to the same IP (especially
        # for cloud-hosted sites like google.com, which can have 50+ subdomains
        # on 5-10 unique IPs). We already have ip_to_ports as a dict keyed by
        # IP, so each IP is scanned exactly once.

        all_services: List[Dict[str, Any]] = []
        unique_ips = list(ip_to_ports.keys())
        self.log.info("Running nmap on %d unique IPs (deduplicated from %d total hosts)",
                      len(unique_ips), len(self.ctx.live_hosts or []))

        # Collect all unique ports across all IPs
        all_ports: Set[int] = set()
        for ports in ip_to_ports.values():
            all_ports.update(ports)
        port_spec = ",".join(str(p) for p in sorted(all_ports))

        # FILTER: nmap is very slow on IPv6 addresses. Only scan IPv4.
        ipv4_ips = [ip for ip in unique_ips if ":" not in ip]
        ipv6_count = len(unique_ips) - len(ipv4_ips)
        if ipv6_count > 0:
            self.log.info("Skipping %d IPv6 addresses (nmap IPv6 is slow)", ipv6_count)

        # CAP: nmap with -sV on many IPs produces huge XML output and takes
        # a very long time. Cap to first 15 IPs to keep scans manageable.
        MAX_NMAP_IPS = 15
        if len(ipv4_ips) > MAX_NMAP_IPS:
            self.log.info("Capping nmap to first %d IPv4 IPs (out of %d)",
                          MAX_NMAP_IPS, len(ipv4_ips))
            ipv4_ips = ipv4_ips[:MAX_NMAP_IPS]

        if not ipv4_ips:
            return ScanResult(
                scanner=self.name, success=True, duration_seconds=0.0,
                data={"services": [], "host_count": 0, "service_count": 0},
            )

        # Run a SINGLE nmap command with all IPv4 IPs and all ports.
        cmd = [
            "nmap",
            "-4",                        # IPv4 only
            "-sV",                       # service/version detection
            "--version-intensity", "3",  # lower intensity = faster
            "-T4",                       # aggressive timing
            "-Pn",                       # skip host discovery
            "-p", port_spec,
            "--max-retries", "1",
            "--host-timeout", f"{settings.nmap_timeout}s",  # per-host cap
            "-oX", "-",                  # XML to stdout
        ]
        # OS detection is OPTIONAL and requires root.
        if os.environ.get("XFINDER_NMAP_OS_DETECT") == "1" and os.geteuid() == 0:
            cmd.insert(1, "-O")
            self.log.info("OS detection enabled (running as root)")

        # nmap accepts multiple targets as positional args
        cmd.extend(ipv4_ips)

        self.log.info("Running nmap on %d IPv4 IPs, ports=%s (host timeout=%ss)",
                      len(ipv4_ips), port_spec, settings.nmap_timeout)

        # Total timeout: per-host (30s) * (num_ips / 5 parallel) + buffer
        total_timeout = settings.nmap_timeout * (len(ipv4_ips) // 5 + 2) + 60
        res = run_subprocess(
            cmd, timeout=total_timeout, retries=1
        )
        if res.timed_out:
            self.log.warning("nmap timed out after %ss", total_timeout)
        elif not res.ok:
            self.log.warning("nmap failed: %s", (res.stderr or "")[:200])
        else:
            # Parse XML — nmap includes all hosts in a single XML document
            for ip in ipv4_ips:
                services = self._parse_nmap_xml(res.stdout, ip)
                all_services.extend(services)

        self.ctx.cache["nmap_results"] = all_services
        # Persist XML even if empty for traceability
        try:
            out_xml.write_text("<nmaprun aggregated='true'/>\n", encoding="utf-8")
        except OSError:
            pass

        self.log.info("nmap detected %d services across %d hosts",
                      len(all_services), len({s["ip"] for s in all_services}))

        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={
                "services": all_services,
                "host_count": len({s["ip"] for s in all_services}),
                "service_count": len(all_services),
            },
        )

    @staticmethod
    def _parse_nmap_xml(xml_text: str, default_ip: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output into flat service records."""
        out: List[Dict[str, Any]] = []
        if not xml_text:
            return out
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return out

        for host in root.findall("host"):
            addr_elem = host.find("address")
            ip = addr_elem.get("addr") if addr_elem is not None else default_ip
            os_name = None
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    os_name = osmatch.get("name")

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port in ports_elem.findall("port"):
                portid = port.get("portid")
                proto = port.get("protocol", "tcp")
                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"
                service_elem = port.find("service")
                service_data: Dict[str, Any] = {
                    "ip": ip,
                    "port": int(portid) if portid else None,
                    "protocol": proto,
                    "state": state,
                    "name": None,
                    "product": None,
                    "version": None,
                    "os": os_name,
                    "extra": None,
                }
                if service_elem is not None:
                    service_data["name"] = service_elem.get("name")
                    service_data["product"] = service_elem.get("product")
                    service_data["version"] = service_elem.get("version")
                    service_data["extra"] = service_elem.get("extrainfo")
                if service_data["port"] is not None:
                    out.append(service_data)
        return out
