"""Database repository layer.

The repository is the ONLY place that touches SQLAlchemy sessions directly.
All other modules call methods on ``Repository`` to persist data, which
keeps transaction boundaries explicit and lets us batch writes for
performance.

The class is intentionally stateless – each method opens its own
``session_scope`` context so we never leak sessions across threads.

All incoming data is sanitized via ``utils.helpers.sanitize_dict`` to strip
NUL bytes and control characters that PostgreSQL TEXT columns reject.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from config.database import session_scope
from database.models import (
    ApiEndpoint,
    CloudAsset,
    DnsRecord,
    HttpInfo,
    IpAddress,
    Port,
    Scan,
    Service,
    Subdomain,
    Target,
    Technology,
    Vulnerability,
)
from utils.helpers import sanitize_dict, sanitize_text

logger = logging.getLogger(__name__)


class Repository:
    """Data-access layer for XFinder.

    All public methods are safe to call from any thread – they open their
    own short-lived session and commit immediately.
    """

    # ----------------------------------------------------------------- targets

    @staticmethod
    def get_or_create_target(domain: str) -> Target:
        """Return an existing target row for *domain*, creating one if needed."""
        with session_scope() as s:
            stmt = select(Target).where(Target.domain == domain)
            target = s.execute(stmt).scalar_one_or_none()
            if target is None:
                target = Target(domain=domain, is_active=True)
                s.add(target)
                s.flush()
                logger.info("Created target id=%s for domain=%s", target.id, domain)
            # detach for caller use
            s.refresh(target)
            return target

    @staticmethod
    def list_targets() -> List[Target]:
        with session_scope() as s:
            stmt = select(Target).order_by(Target.domain)
            return list(s.execute(stmt).scalars())

    # ----------------------------------------------------------------- scans

    @staticmethod
    def start_scan(target_id: int, scan_type: str, output_dir: Optional[str] = None) -> Scan:
        """Create a new Scan row in 'running' status and return it."""
        with session_scope() as s:
            scan = Scan(
                target_id=target_id,
                scan_type=scan_type,
                status="running",
                started_at=datetime.utcnow(),
                output_dir=output_dir,
            )
            s.add(scan)
            s.flush()
            s.refresh(scan)
            logger.info("Started scan id=%s type=%s target=%s", scan.id, scan_type, target_id)
            return scan

    @staticmethod
    def finish_scan(scan_id: int, status: str = "completed", error: Optional[str] = None) -> None:
        """Mark a scan as finished, recording duration."""
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if scan is None:
                logger.error("finish_scan: scan %s not found", scan_id)
                return
            scan.finished_at = datetime.utcnow()
            scan.duration_seconds = (scan.finished_at - scan.started_at).total_seconds()
            scan.status = status
            scan.error = error
            logger.info(
                "Finished scan id=%s status=%s duration=%.2fs",
                scan_id, status, scan.duration_seconds or 0.0,
            )

    @staticmethod
    def get_scan(scan_id: int) -> Optional[Scan]:
        with session_scope() as s:
            return s.get(Scan, scan_id)

    @staticmethod
    def list_scans_for_target(target_id: int, limit: int = 50) -> List[Scan]:
        with session_scope() as s:
            stmt = (
                select(Scan)
                .where(Scan.target_id == target_id)
                .order_by(desc(Scan.started_at))
                .limit(limit)
            )
            return list(s.execute(stmt).scalars())

    @staticmethod
    def get_previous_scan(scan_id: int, target_id: int) -> Optional[Scan]:
        """Return the most recent completed scan before *scan_id* for the target."""
        with session_scope() as s:
            current = s.get(Scan, scan_id)
            if current is None:
                return None
            stmt = (
                select(Scan)
                .where(
                    Scan.target_id == target_id,
                    Scan.id < scan_id,
                    Scan.status == "completed",
                )
                .order_by(desc(Scan.started_at))
                .limit(1)
            )
            return s.execute(stmt).scalar_one_or_none()

    # ----------------------------------------------------------------- subdomains

    @staticmethod
    def bulk_insert_subdomains(
        scan_id: int, target_id: int, names: Iterable[str], source: str = "subfinder"
    ) -> int:
        """Insert subdomains, skipping duplicates within this scan.

        Returns the number of rows actually inserted.
        """
        with session_scope() as s:
            existing = {
                row.name
                for row in s.execute(
                    select(Subdomain.name).where(Subdomain.scan_id == scan_id)
                )
            }
            inserted = 0
            for name in names:
                if not name or name in existing:
                    continue
                s.add(
                    Subdomain(
                        scan_id=scan_id,
                        target_id=target_id,
                        name=name,
                        source=source,
                    )
                )
                existing.add(name)
                inserted += 1
            s.flush()
            logger.info("Inserted %d subdomains for scan %s", inserted, scan_id)
            return inserted

    @staticmethod
    def mark_subdomain_resolved(subdomain_id: int, resolved: bool = True) -> None:
        with session_scope() as s:
            sd = s.get(Subdomain, subdomain_id)
            if sd is not None:
                sd.is_resolved = resolved

    @staticmethod
    def mark_subdomain_live(subdomain_id: int, live: bool = True) -> None:
        with session_scope() as s:
            sd = s.get(Subdomain, subdomain_id)
            if sd is not None:
                sd.is_live_http = live

    @staticmethod
    def list_subdomains_for_scan(scan_id: int) -> List[Subdomain]:
        with session_scope() as s:
            stmt = select(Subdomain).where(Subdomain.scan_id == scan_id)
            return list(s.execute(stmt).scalars())

    @staticmethod
    def get_subdomain_by_name(scan_id: int, name: str) -> Optional[Subdomain]:
        with session_scope() as s:
            stmt = select(Subdomain).where(Subdomain.scan_id == scan_id, Subdomain.name == name)
            return s.execute(stmt).scalar_one_or_none()

    # ----------------------------------------------------------------- dns

    @staticmethod
    def bulk_insert_dns_records(
        scan_id: int, subdomain_id: int, records: Iterable[Dict[str, Any]]
    ) -> int:
        with session_scope() as s:
            inserted = 0
            for rec in records:
                rec = sanitize_dict(rec) if rec else {}
                s.add(
                    DnsRecord(
                        scan_id=scan_id,
                        subdomain_id=subdomain_id,
                        record_type=sanitize_text(rec.get("type", ""), 8).upper(),
                        value=sanitize_text(str(rec.get("value", "")), 10000),
                        ttl=rec.get("ttl"),
                    )
                )
                inserted += 1
            s.flush()
            return inserted

    # ----------------------------------------------------------------- http

    @staticmethod
    def upsert_http_info(scan_id: int, subdomain_id: int, data: Dict[str, Any]) -> HttpInfo:
        with session_scope() as s:
            existing = s.execute(
                select(HttpInfo).where(HttpInfo.subdomain_id == subdomain_id)
            ).scalar_one_or_none()
            if existing is None:
                existing = HttpInfo(scan_id=scan_id, subdomain_id=subdomain_id)
                s.add(existing)
            data = sanitize_dict(data) if data else {}
            for k, v in data.items():
                if hasattr(existing, k) and v is not None:
                    if isinstance(v, (list, dict)):
                        setattr(existing, k, sanitize_text(json.dumps(v, ensure_ascii=False), 10000))
                    else:
                        setattr(existing, k, sanitize_text(v, 2048))
            s.flush()
            s.refresh(existing)
            return existing

    # ----------------------------------------------------------------- cloud

    @staticmethod
    def upsert_cloud_asset(scan_id: int, subdomain_id: int, data: Dict[str, Any]) -> None:
        with session_scope() as s:
            existing = s.execute(
                select(CloudAsset).where(CloudAsset.subdomain_id == subdomain_id)
            ).scalar_one_or_none()
            if existing is None:
                existing = CloudAsset(scan_id=scan_id, subdomain_id=subdomain_id)
                s.add(existing)
            data = sanitize_dict(data) if data else {}
            for k, v in data.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, sanitize_text(v, 256))
            s.flush()

    # ----------------------------------------------------------------- ip / port / service

    @staticmethod
    def upsert_ip_address(
        scan_id: int, subdomain_id: int, data: Dict[str, Any]
    ) -> IpAddress:
        with session_scope() as s:
            data = sanitize_dict(data) if data else {}
            existing = s.execute(
                select(IpAddress).where(
                    IpAddress.scan_id == scan_id,
                    IpAddress.subdomain_id == subdomain_id,
                    IpAddress.address == data.get("address"),
                )
            ).scalar_one_or_none()
            if existing is None:
                existing = IpAddress(
                    scan_id=scan_id,
                    subdomain_id=subdomain_id,
                    address=data.get("address"),
                )
                s.add(existing)
            for k, v in data.items():
                if hasattr(existing, k) and v is not None:
                    setattr(existing, k, sanitize_text(v, 256))
            s.flush()
            s.refresh(existing)
            return existing

    @staticmethod
    def add_port(
        scan_id: int, ip_address_id: int, port: int, protocol: str = "tcp",
        state: str = "open",
    ) -> Port:
        with session_scope() as s:
            obj = Port(
                scan_id=scan_id,
                ip_address_id=ip_address_id,
                port=port,
                protocol=protocol,
                state=state,
            )
            s.add(obj)
            s.flush()
            s.refresh(obj)
            return obj

    @staticmethod
    def add_service(
        scan_id: int, port_id: int, data: Dict[str, Any]
    ) -> None:
        with session_scope() as s:
            data = sanitize_dict(data) if data else {}
            extra_val = data.get("extra")
            obj = Service(
                scan_id=scan_id,
                port_id=port_id,
                name=sanitize_text(data.get("name"), 64),
                product=sanitize_text(data.get("product"), 128),
                version=sanitize_text(data.get("version"), 128),
                os=sanitize_text(data.get("os"), 128),
                extra=sanitize_text(
                    json.dumps(extra_val, ensure_ascii=False) if extra_val is not None else None,
                    10000
                ),
            )
            s.add(obj)
            s.flush()

    # ----------------------------------------------------------------- technologies

    @staticmethod
    def bulk_insert_technologies(
        scan_id: int, http_info_id: int, techs: Iterable[Dict[str, Any]]
    ) -> int:
        with session_scope() as s:
            inserted = 0
            for t in techs:
                t = sanitize_dict(t) if t else {}
                s.add(
                    Technology(
                        scan_id=scan_id,
                        http_info_id=http_info_id,
                        category=sanitize_text(t.get("category"), 64),
                        name=sanitize_text(t.get("name", "unknown"), 128),
                        version=sanitize_text(t.get("version"), 64),
                    )
                )
                inserted += 1
            s.flush()
            return inserted

    # ----------------------------------------------------------------- api endpoints

    @staticmethod
    def bulk_insert_api_endpoints(
        scan_id: int, endpoints: Iterable[Dict[str, Any]]
    ) -> int:
        with session_scope() as s:
            inserted = 0
            for ep in endpoints:
                # Sanitize to strip NUL bytes that PostgreSQL rejects
                ep = sanitize_dict(ep) if ep else {}
                s.add(
                    ApiEndpoint(
                        scan_id=scan_id,
                        source_host=sanitize_text(ep.get("source_host", ""), 253),
                        method=sanitize_text(ep.get("method"), 8),
                        url=sanitize_text(ep.get("url", ""), 2048),
                        body=sanitize_text(ep.get("body"), 10000),
                        tag=sanitize_text(ep.get("tag"), 32),
                    )
                )
                inserted += 1
            s.flush()
            return inserted

    # ----------------------------------------------------------------- vulnerabilities

    @staticmethod
    def bulk_insert_vulnerabilities(
        scan_id: int, vulns: Iterable[Dict[str, Any]]
    ) -> int:
        with session_scope() as s:
            inserted = 0
            for v in vulns:
                # Sanitize to strip NUL bytes that PostgreSQL rejects
                v = sanitize_dict(v) if v else {}
                refs = v.get("reference")
                if isinstance(refs, list):
                    refs = "\n".join(str(r) for r in refs)
                tags = v.get("tags")
                if isinstance(tags, list):
                    tags = ",".join(str(t) for t in tags)
                info = v.get("info", {}) if isinstance(v.get("info"), dict) else {}
                s.add(
                    Vulnerability(
                        scan_id=scan_id,
                        template_id=sanitize_text(v.get("template-id") or v.get("template_id") or "unknown", 128),
                        name=sanitize_text(info.get("name") or v.get("name"), 512),
                        severity=sanitize_text(info.get("severity") or v.get("severity"), 16),
                        description=sanitize_text(info.get("description") or v.get("description"), 10000),
                        matched_url=sanitize_text(v.get("matched-url") or v.get("matched_url"), 2048),
                        matched_at=sanitize_text(v.get("matched-at") or v.get("matched_at"), 2048),
                        evidence=sanitize_text(v.get("extracted-results") or v.get("evidence"), 10000),
                        reference_urls=sanitize_text(refs, 10000),
                        tags=sanitize_text(tags, 256),
                        cvss_score=(
                            info.get("classification", {}).get("cvss-score")
                            if isinstance(info.get("classification"), dict)
                            else None
                        ),
                    )
                )
                inserted += 1
            s.flush()
            logger.info("Inserted %d vulnerabilities for scan %s", inserted, scan_id)
            return inserted

    # ----------------------------------------------------------------- analytics for change detection

    @staticmethod
    def get_scan_summary(scan_id: int) -> Dict[str, Any]:
        """Return a normalized summary of a scan, used for change detection."""
        with session_scope() as s:
            subdomains = s.execute(
                select(Subdomain.name).where(Subdomain.scan_id == scan_id)
            ).scalars().all()

            dns_rows = s.execute(
                select(DnsRecord.subdomain_id, DnsRecord.record_type, DnsRecord.value)
                .where(DnsRecord.scan_id == scan_id)
            ).all()

            http_rows = s.execute(
                select(HttpInfo.subdomain_id, HttpInfo.status_code, HttpInfo.webserver, HttpInfo.title)
                .where(HttpInfo.scan_id == scan_id)
            ).all()

            ip_rows = s.execute(
                select(IpAddress.subdomain_id, IpAddress.address, IpAddress.asn, IpAddress.country)
                .where(IpAddress.scan_id == scan_id)
            ).all()

            port_rows = s.execute(
                select(Port.ip_address_id, Port.port, Port.protocol, Port.state)
                .where(Port.scan_id == scan_id)
            ).all()

            cloud_rows = s.execute(
                select(CloudAsset.subdomain_id, CloudAsset.provider, CloudAsset.cdn, CloudAsset.waf)
                .where(CloudAsset.scan_id == scan_id)
            ).all()

            tech_rows = s.execute(
                select(Technology.http_info_id, Technology.category, Technology.name, Technology.version)
                .where(Technology.scan_id == scan_id)
            ).all()

            vuln_rows = s.execute(
                select(Vulnerability.template_id, Vulnerability.severity, Vulnerability.matched_url)
                .where(Vulnerability.scan_id == scan_id)
            ).all()

            api_rows = s.execute(
                select(ApiEndpoint.url).where(ApiEndpoint.scan_id == scan_id)
            ).scalars().all()

        return {
            "scan_id": scan_id,
            "subdomains": sorted(subdomains),
            "dns": [
                {"subdomain_id": r[0], "type": r[1], "value": r[2]} for r in dns_rows
            ],
            "http": [
                {"subdomain_id": r[0], "status": r[1], "server": r[2], "title": r[3]}
                for r in http_rows
            ],
            "ips": [
                {"subdomain_id": r[0], "address": r[1], "asn": r[2], "country": r[3]}
                for r in ip_rows
            ],
            "ports": [
                {"ip_id": r[0], "port": r[1], "proto": r[2], "state": r[3]}
                for r in port_rows
            ],
            "cloud": [
                {"subdomain_id": r[0], "provider": r[1], "cdn": r[2], "waf": r[3]}
                for r in cloud_rows
            ],
            "technologies": [
                {"http_info_id": r[0], "category": r[1], "name": r[2], "version": r[3]}
                for r in tech_rows
            ],
            "vulnerabilities": [
                {"template_id": r[0], "severity": r[1], "url": r[2]} for r in vuln_rows
            ],
            "api_endpoints": sorted(api_rows),
        }
