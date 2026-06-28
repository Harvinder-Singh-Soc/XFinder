"""Subfinder wrapper – passive subdomain enumeration.

Subfinder's ``-all`` flag attempts to query EVERY configured source
(including paid APIs like GitHub, Shodan, Censys, etc.). When those API
keys are not configured, subfinder waits the full timeout per source and
the overall scan can take 10+ minutes and return 0 results.

This wrapper:
* Uses ``-all`` only when the user explicitly requests it via env var
  ``XFINDER_SUBFINDER_ALL=1``. Default is the fast passive mode.
* Sets a hard overall timeout (default 90s) so we never hang for minutes.
* Falls back to a retry with higher timeout if the first attempt fails.
* Always returns the apex domain itself as a subdomain if subfinder
  returns nothing, so downstream scanners have at least one host to try.
"""

from __future__ import annotations

import os

from config.settings import settings
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess


class SubfinderScanner(BaseScanner):
    name = "subfinder"
    description = "Passive subdomain enumeration using Subfinder"
    required_tools = ["subfinder"]

    def run(self) -> ScanResult:
        # Build command. -all is opt-in because it requires API keys
        # to be useful; without them it just hangs and returns 0.
        use_all = os.environ.get("XFINDER_SUBFINDER_ALL", "0") == "1"

        cmd = [
            "subfinder",
            "-d", self.ctx.target,
            "-silent",
            "-recursive",
            "-timeout", str(settings.dnsx_timeout),  # per-source DNS timeout
            "-t", str(self.ctx.threads),
        ]
        if use_all:
            cmd.insert(-1, "-all")
            mode = "all sources (slow, needs API keys)"
        else:
            mode = "passive sources (fast, no API keys needed)"

        # Hard overall cap: 90 seconds default. Without this cap, subfinder
        # can hang for 6-12 minutes on large targets with no API keys.
        # Override with XFINDER_SUBFINDER_TIMEOUT env var if needed.
        overall_timeout = int(os.environ.get("XFINDER_SUBFINDER_TIMEOUT", "90"))

        self.log.info("Running subfinder on %s [%s] (overall cap=%ss)",
                      self.ctx.target, mode, overall_timeout)
        self.log.debug("subfinder command: %s", " ".join(cmd))
        res = run_subprocess(cmd, timeout=overall_timeout, retries=1)

        if res.timed_out:
            self.log.warning("subfinder timed out after %ss, using fallback",
                             overall_timeout)
            # Fallback: at least include the apex domain itself
            subdomains = self._fallback_subdomains()
            self.ctx.subdomains = subdomains
            return ScanResult(
                scanner=self.name, success=True, duration_seconds=0.0,
                data={"subdomains": subdomains, "count": len(subdomains)},
                error=f"subfinder timed out after {overall_timeout}s, using fallback (apex + www)",
            )
        if not res.ok:
            stderr_prev = (res.stderr or "")[:300]
            self.log.warning("subfinder failed: %s, using fallback", stderr_prev)
            subdomains = self._fallback_subdomains()
            self.ctx.subdomains = subdomains
            return ScanResult(
                scanner=self.name, success=True, duration_seconds=0.0,
                data={"subdomains": subdomains, "count": len(subdomains)},
                error=f"subfinder failed, using fallback: {stderr_prev}",
            )

        subdomains = sorted({
            line.strip().lower()
            for line in res.stdout.splitlines()
            if line.strip() and not line.startswith("[")
        })
        self.log.info("subfinder returned %d subdomains", len(subdomains))

        # If subfinder returned nothing, fall back to apex + www so
        # downstream scanners have at least one host to probe.
        if not subdomains:
            self.log.warning(
                "subfinder returned 0 subdomains for %s. Using fallback "
                "(apex + www). Possible causes:\n"
                "  1. Subfinder API keys not configured\n"
                "  2. Network blocking outbound DNS/HTTPS\n"
                "  3. The domain has no public subdomains\n"
                "Configure API keys: subfinder -h (see provider-config.yaml)",
                self.ctx.target,
            )
            subdomains = self._fallback_subdomains()

        # Cache for downstream scanners
        self.ctx.subdomains = subdomains
        return ScanResult(
            scanner=self.name, success=True, duration_seconds=0.0,
            data={"subdomains": subdomains, "count": len(subdomains)},
            raw_output=res.stdout,
        )

    def _fallback_subdomains(self) -> list:
        """Return a minimal fallback list: apex domain + www subdomain.

        This ensures downstream scanners (dnsx, httpx, etc.) always have
        at least one host to probe, even if subfinder fails completely.
        """
        target = self.ctx.target.strip().lower().rstrip(".")
        return [target, f"www.{target}"]
