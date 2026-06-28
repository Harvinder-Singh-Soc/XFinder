"""Nuclei wrapper – template-based vulnerability scanning.

Tested against nuclei v3.9.0+. Flag changes vs older versions:

* ``-json`` → ``-j`` (or ``-jsonl``) for JSONL output
* ``-concurrency`` → ``-c`` (full name still works as alias)
* ``-timeout`` still works
* ``-retries`` still works

Runs only against live HTTP/HTTPS hosts (per the optimized workflow) and
uses technology-aware template selection when httpx technologies are
available in the scan context cache.
"""

from __future__ import annotations

from typing import Any, Dict, List

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess, safe_jsonl_loads


class NucleiScanner(BaseScanner):
    name = "nuclei"
    description = "Vulnerability scanning using Nuclei templates"
    required_tools = ["nuclei"]

    def run(self) -> ScanResult:
        live_hosts: List[str] = self.ctx.live_hosts or []
        if not live_hosts:
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error="No live hosts to scan (run httpx first)",
            )

        # CAP the number of hosts we scan to avoid extremely long scans.
        # Nuclei with 6700+ templates on 40+ hosts can take hours.
        MAX_NUCLEI_HOSTS = 5
        if len(live_hosts) > MAX_NUCLEI_HOSTS:
            self.log.info("Capping nuclei to first %d live hosts (out of %d)",
                          MAX_NUCLEI_HOSTS, len(live_hosts))
            live_hosts = live_hosts[:MAX_NUCLEI_HOSTS]

        stdin = "\n".join(live_hosts)
        cmd = [
            "nuclei",
            "-silent",
            "-j",                  # JSONL output (was -json in v2)
            "-duc",                # disable update check
            "-nc",                 # no color
            "-c", str(min(self.ctx.threads, 25)),  # concurrency
            "-timeout", str(settings.httpx_timeout),  # per-host timeout
            "-retries", "1",
            "-severity", ",".join(_severity_filter()),
        ]
        # Technology-aware template selection
        tech_tags = self._tech_tags()
        if tech_tags:
            cmd.extend(["-tags", ",".join(tech_tags)])

        self.log.info("Running nuclei on %d live hosts (severity=%s, tags=%s)",
                      len(live_hosts), settings.nuclei_severity,
                      ",".join(tech_tags) if tech_tags else "(none, default templates)")
        self.log.debug("nuclei command: %s", " ".join(cmd))
        # Nuclei can take a long time with 6000+ templates. Use nuclei_timeout
        # as the overall scan timeout.
        res = run_subprocess(
            cmd, timeout=settings.nuclei_timeout, retries=1, input_text=stdin
        )
        if res.timed_out:
            # Even on timeout, we may have partial results in stdout
            self.log.warning("nuclei timed out after %ss, parsing partial results",
                             settings.nuclei_timeout)
        elif res.stderr and not res.stdout.strip():
            stderr_preview = res.stderr.strip()[:500]
            self.log.error("nuclei produced no output. stderr: %s", stderr_preview)
            return ScanResult(
                scanner=self.name, success=False, duration_seconds=0.0,
                error=f"nuclei produced no output. stderr: {stderr_preview}",
                raw_output=res.stdout,
            )

        findings: List[Dict[str, Any]] = safe_jsonl_loads(res.stdout)
        # Normalize finding keys (Nuclei uses kebab-case)
        normalized: List[Dict[str, Any]] = []
        for f in findings:
            info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
            normalized.append({
                "template-id": f.get("template-id") or f.get("templateID") or f.get("template"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "description": info.get("description"),
                "matched-url": f.get("matched-url") or f.get("matched-at") or f.get("url"),
                "matched-at": f.get("matched-at"),
                "extracted-results": f.get("extracted-results"),
                "reference": info.get("reference"),
                "tags": info.get("tags"),
                "classification": info.get("classification"),
            })

        self.ctx.cache["nuclei_results"] = normalized
        self.log.info("nuclei found %d vulnerabilities", len(normalized))

        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={
                "vulnerabilities": normalized,
                "count": len(normalized),
                "by_severity": _group_by_severity(normalized),
            },
            raw_output=res.stdout,
        )

    # ------------------------------------------------------------- helpers

    def _tech_tags(self) -> List[str]:
        """Return Nuclei tags derived from httpx-detected technologies."""
        techs: List[str] = []
        for host_info in self.ctx.cache.get("http_results", []):
            for t in host_info.get("technologies", []) or []:
                techs.append(str(t).lower())

        tag_map = {
            "wordpress": "wordpress",
            "wordpress cms": "wordpress",
            "nginx": "nginx",
            "apache": "apache",
            "iis": "iis",
            "tomcat": "tomcat",
            "jenkins": "jenkins",
            "gitlab": "gitlab",
            "grafana": "grafana",
            "kibana": "kibana",
            "elasticsearch": "elasticsearch",
            "redis": "redis",
            "php": "php",
            "joomla": "joomla",
            "drupal": "drupal",
            "node.js": "nodejs",
            "express": "express",
            "django": "django",
            "flask": "flask",
            "spring": "spring",
            "struts": "struts",
        }
        tags: List[str] = []
        for t in techs:
            for key, tag in tag_map.items():
                if key in t and tag not in tags:
                    tags.append(tag)
        return tags


def _severity_filter() -> List[str]:
    """Return configured severity levels for Nuclei."""
    return settings.nuclei_severities


def _group_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
