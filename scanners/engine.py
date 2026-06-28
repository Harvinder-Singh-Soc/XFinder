"""Scan orchestration engine.

The engine is the glue between scanners, the database, and the report
writer. It:

1. Resolves the ordered scanner chain for a scan type.
2. Builds a ``ScanContext`` shared between scanners.
3. Runs each scanner, persisting intermediate results to PostgreSQL and
   writing per-scan JSON files in real time so partial results survive
   a crash.
4. Marks the Scan row as completed/failed.
5. Triggers change detection against the previous scan.
6. Returns a structured ``ScanOutcome`` for the CLI to display.

The engine never imports concrete scanner classes — it uses the registry.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from config.settings import settings
from database.models import Subdomain
from database.repository import Repository
from reports.json_export import JsonExporter
from scanners.base import BaseScanner, ScanContext, ScanResult
from scanners.registry import get_scanner
from utils.helpers import ensure_dir, timestamp_str, write_json
from utils.logger import get_logger

logger = get_logger(__name__)


# --------------------------------------------------------------------------- outcome

@dataclass(slots=True)
class ScanOutcome:
    """Structured result returned by ``ScanEngine.run``."""

    scan_id: int
    target: str
    scan_type: str
    success: bool
    duration_seconds: float
    scanner_results: Dict[str, ScanResult] = field(default_factory=dict)
    error: Optional[str] = None
    output_dir: Optional[str] = None
    changes: Optional[Dict[str, Any]] = None


# --------------------------------------------------------------------------- engine

class ScanEngine:
    """Coordinates execution of a chain of scanners for a single target."""

    def __init__(self, repository: Optional[Repository] = None) -> None:
        # ``Repository`` is all static methods, so the instance is purely
        # cosmetic — but accepting it as a dependency makes the engine
        # easier to mock in tests.
        self.repo = repository or Repository()

    # ----------------------------------------------------------------- public API

    def run(
        self,
        target: str,
        scan_type: str,
        threads: Optional[int] = None,
        timeout: Optional[int] = None,
        rate: Optional[int] = None,
    ) -> ScanOutcome:
        """Execute a full scan workflow and persist all results."""
        target = target.strip().lower()
        start = time.time()
        logger.info("ScanEngine starting: target=%s type=%s", target, scan_type)

        # 1. Target + Scan rows
        target_obj = self.repo.get_or_create_target(target)
        output_dir = self._make_output_dir(target)
        scan = self.repo.start_scan(target_obj.id, scan_type, output_dir=str(output_dir))

        # 2. Context
        ctx = ScanContext(
            target=target,
            scan_id=scan.id,
            target_id=target_obj.id,
            output_dir=str(output_dir),
            threads=threads or settings.default_threads,
            timeout=timeout or settings.nmap_timeout,
            rate=rate or settings.scan_rate,
        )

        # 3. Run scanner chain
        scanner_classes = get_scanner(scan_type)
        outcomes: Dict[str, ScanResult] = {}
        try:
            for cls in scanner_classes:
                result = self._run_scanner(cls, ctx)
                outcomes[cls.name] = result
                # Persist intermediate data immediately so a crash mid-scan
                # still leaves partial results in the database.
                self._persist_result(cls, ctx, result)
                self._write_intermediate_json(cls, ctx, result, output_dir)

            # 4. Change detection vs previous scan
            changes = self._compute_changes(scan.id, target_obj.id)

            # 5. Finalize scan
            self.repo.finish_scan(scan.id, status="completed")
            duration = time.time() - start

            # 6. Write changes.json + full_scan.json
            write_json(Path(output_dir) / "changes.json", changes)
            write_json(
                Path(output_dir) / "full_scan.json",
                self._build_full_summary(target, scan_type, scan.id, outcomes, duration, changes),
            )

            return ScanOutcome(
                scan_id=scan.id,
                target=target,
                scan_type=scan_type,
                success=True,
                duration_seconds=duration,
                scanner_results=outcomes,
                output_dir=str(output_dir),
                changes=changes,
            )
        except Exception as exc:
            logger.exception("ScanEngine failed: %s", exc)
            self.repo.finish_scan(scan.id, status="failed", error=str(exc))
            return ScanOutcome(
                scan_id=scan.id,
                target=target,
                scan_type=scan_type,
                success=False,
                duration_seconds=time.time() - start,
                scanner_results=outcomes,
                error=str(exc),
                output_dir=str(output_dir),
            )

    # ----------------------------------------------------------------- internals

    def _run_scanner(self, cls: Type[BaseScanner], ctx: ScanContext) -> ScanResult:
        """Instantiate and execute a single scanner."""
        scanner = cls(ctx)
        return scanner.execute()

    def _persist_result(
        self,
        cls: Type[BaseScanner],
        ctx: ScanContext,
        result: ScanResult,
    ) -> None:
        """Persist scanner output to the database (best-effort)."""
        try:
            if cls.name == "subfinder":
                self.repo.bulk_insert_subdomains(
                    ctx.scan_id, ctx.target_id, result.data.get("subdomains", []),
                    source="subfinder",
                )
            elif cls.name == "dnsx":
                self._persist_dns(ctx, result)
            elif cls.name == "httpx":
                self._persist_http(ctx, result)
            elif cls.name == "naabu":
                self._persist_naabu(ctx, result)
            elif cls.name == "nmap":
                self._persist_nmap(ctx, result)
            elif cls.name == "katana":
                self.repo.bulk_insert_api_endpoints(
                    ctx.scan_id, result.data.get("endpoints", [])
                )
            elif cls.name == "nuclei":
                self.repo.bulk_insert_vulnerabilities(
                    ctx.scan_id, result.data.get("vulnerabilities", [])
                )
        except Exception as exc:
            logger.error("Persisting %s results failed: %s", cls.name, exc, exc_info=True)

    def _persist_dns(self, ctx: ScanContext, result: ScanResult) -> None:
        """Persist DNS records, grouping by host -> subdomain_id."""
        records = result.data.get("records", [])
        # Index subdomains by name for fast lookup
        subdomains = {sd.name: sd for sd in self.repo.list_subdomains_for_scan(ctx.scan_id)}
        # Also insert the apex target itself as a subdomain-equivalent
        apex = subdomains.get(ctx.target)
        if apex is None:
            self.repo.bulk_insert_subdomains(ctx.scan_id, ctx.target_id, [ctx.target], source="apex")
            subdomains = {sd.name: sd for sd in self.repo.list_subdomains_for_scan(ctx.scan_id)}
            apex = subdomains.get(ctx.target)

        # Group records by host
        grouped: Dict[str, List[dict]] = {}
        for rec in records:
            grouped.setdefault(rec["host"], []).append(rec)

        for host, host_records in grouped.items():
            sd = subdomains.get(host)
            if sd is None:
                # Insert this subdomain on the fly
                self.repo.bulk_insert_subdomains(ctx.scan_id, ctx.target_id, [host], source="dnsx")
                sd = self.repo.get_subdomain_by_name(ctx.scan_id, host)
                if sd is None:
                    continue
            self.repo.bulk_insert_dns_records(ctx.scan_id, sd.id, host_records)
            # Mark resolved
            self.repo.mark_subdomain_resolved(sd.id, resolved=True)

    def _persist_http(self, ctx: ScanContext, result: ScanResult) -> None:
        http_results = result.data.get("hosts", [])
        subdomains = {sd.name: sd for sd in self.repo.list_subdomains_for_scan(ctx.scan_id)}

        for h in http_results:
            host = (h.get("host") or "").lower()
            if not host:
                continue
            # Make sure subdomain row exists
            sd = subdomains.get(host)
            if sd is None:
                self.repo.bulk_insert_subdomains(ctx.scan_id, ctx.target_id, [host], source="httpx")
                sd = self.repo.get_subdomain_by_name(ctx.scan_id, host)
                if sd is None:
                    continue
                subdomains[host] = sd
            # Insert HTTP info
            self.repo.upsert_http_info(ctx.scan_id, sd.id, {
                "url": h.get("url", ""),
                "final_url": h.get("final_url"),
                "status_code": h.get("status_code"),
                "title": h.get("title"),
                "server_header": h.get("server_header"),
                "content_length": h.get("content_length"),
                "response_time_ms": h.get("response_time_ms"),
                "scheme": h.get("scheme"),
                "webserver": h.get("webserver"),
                "tech_blob": h.get("technologies"),
            })
            self.repo.mark_subdomain_live(sd.id, live=True)

            # IP addresses
            for ip in h.get("ips", []) or []:
                self.repo.upsert_ip_address(ctx.scan_id, sd.id, {"address": ip})

            # Technologies
            techs = h.get("technologies", []) or []
            if techs:
                http_info = self.repo.upsert_http_info(ctx.scan_id, sd.id, {
                    "url": h.get("url", ""),
                })
                self.repo.bulk_insert_technologies(
                    ctx.scan_id, http_info.id, [
                        {"name": t, "category": "Detected"} for t in techs
                    ]
                )

    def _persist_naabu(self, ctx: ScanContext, result: ScanResult) -> None:
        open_ports = result.data.get("open_ports", [])
        # Group by IP for upsert
        for entry in open_ports:
            ip = entry.get("ip")
            if not ip:
                continue
            # We need a subdomain to attach the IP to. Find one whose address matches.
            ip_obj = self.repo.upsert_ip_address(ctx.scan_id, _find_subdomain_for_ip(ctx, ip), {"address": ip})
            self.repo.add_port(
                ctx.scan_id, ip_obj.id, int(entry["port"]),
                protocol=entry.get("protocol", "tcp"), state="open",
            )

    def _persist_nmap(self, ctx: ScanContext, result: ScanResult) -> None:
        services = result.data.get("services", [])
        # Build (ip, port) -> port_id lookup by walking through inserted ports.
        # For simplicity, re-query the ports inserted by naabu.
        from sqlalchemy import select
        from config.database import session_scope
        from database.models import Port, IpAddress
        with session_scope() as s:
            port_lookup = {}
            for p in s.execute(
                select(Port).where(Port.scan_id == ctx.scan_id)
            ).scalars():
                ip_addr = s.get(IpAddress, p.ip_address_id)
                if ip_addr:
                    port_lookup[(ip_addr.address, p.port)] = p.id

        for svc in services:
            key = (svc.get("ip"), svc.get("port"))
            port_id = port_lookup.get(key)
            if port_id is None:
                continue
            self.repo.add_service(ctx.scan_id, port_id, svc)

    def _write_intermediate_json(
        self, cls: Type[BaseScanner], ctx: ScanContext,
        result: ScanResult, output_dir: Path,
    ) -> None:
        """Write the per-scanner JSON file (e.g. ``subdomains.json``)."""
        filename_map = {
            "subfinder": "subdomains.json",
            "dnsx": "dns.json",
            "httpx": "http.json",
            "naabu": "ports.json",
            "nmap": "services.json",
            "katana": "api.json",
            "nuclei": "vulnerabilities.json",
        }
        fname = filename_map.get(cls.name)
        if not fname:
            return
        write_json(output_dir / fname, {
            "scanner": cls.name,
            "success": result.success,
            "duration_seconds": result.duration_seconds,
            "error": result.error,
            "data": result.data,
        })

    def _compute_changes(self, scan_id: int, target_id: int) -> Dict[str, Any]:
        """Compare this scan to the previous one for the same target."""
        from reports.json_export import JsonExporter
        current = self.repo.get_scan_summary(scan_id)
        prev_scan = self.repo.get_previous_scan(scan_id, target_id)
        if prev_scan is None:
            return {"first_scan": True, "changes": {}}
        previous = self.repo.get_scan_summary(prev_scan.id)
        return JsonExporter.compute_changes(previous, current)

    def _make_output_dir(self, target: str) -> Path:
        """Create and return ``output/<target>/<timestamp>/``."""
        ts = timestamp_str()
        out = Path(settings.output_path) / target / ts
        return ensure_dir(out)

    def _build_full_summary(
        self, target: str, scan_type: str, scan_id: int,
        outcomes: Dict[str, ScanResult], duration: float,
        changes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build the consolidated ``full_scan.json`` payload."""
        return {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": round(duration, 2),
            "scanners": {
                name: {
                    "success": r.success,
                    "duration_seconds": round(r.duration_seconds, 2),
                    "error": r.error,
                    "summary": {k: v for k, v in r.data.items()
                                if k not in {"raw_output"}},
                }
                for name, r in outcomes.items()
            },
            "changes": changes,
        }


def _find_subdomain_for_ip(ctx: ScanContext, ip: str) -> int:
    """Best-effort lookup: find any subdomain in this scan that resolved to *ip*.

    Falls back to the apex target subdomain if no match is found.
    """
    from sqlalchemy import select
    from config.database import session_scope
    from database.models import DnsRecord, Subdomain
    with session_scope() as s:
        row = s.execute(
            select(DnsRecord.subdomain_id)
            .where(DnsRecord.scan_id == ctx.scan_id, DnsRecord.record_type == "A",
                   DnsRecord.value == ip)
            .limit(1)
        ).first()
        if row:
            return row[0]
        # Fall back to apex
        sd = s.execute(
            select(Subdomain).where(
                Subdomain.scan_id == ctx.scan_id, Subdomain.name == ctx.target
            )
        ).scalar_one_or_none()
        if sd:
            return sd.id
        # Last resort: insert an "unknown" subdomain row so the FK is satisfied
        from database.repository import Repository
        Repository.bulk_insert_subdomains(ctx.scan_id, ctx.target_id, [ip], source="naabu")
        sd = s.execute(
            select(Subdomain).where(
                Subdomain.scan_id == ctx.scan_id, Subdomain.name == ip
            )
        ).scalar_one()
        return sd.id
