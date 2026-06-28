"""SQLAlchemy ORM models for XFinder.

Schema overview
----------------

* ``Target``        – a top-level domain being tracked (e.g. example.com).
* ``Scan``          – one execution of a scan workflow against a target.
* ``Subdomain``     – a discovered subdomain under a target.
* ``DnsRecord``     – DNS record (A/AAAA/CNAME/MX/TXT/NS/SOA) per subdomain.
* ``HttpInfo``      – HTTP fingerprint for a live subdomain.
* ``CloudAsset``    – cloud-hosting classification for a subdomain.
* ``IpAddress``     – resolved IP address for a subdomain.
* ``Port``          – open port on an IP.
* ``Service``       – service/version/OS detection on a port.
* ``Technology``    – detected technology on an HTTP service.
* ``ApiEndpoint``   – crawled endpoint / API path.
* ``Vulnerability`` – Nuclei finding.

Every row is scoped by ``scan_id`` so historical scans never overwrite each
other. ``created_at`` is set on insert; nothing is ever deleted by the
application (history is append-only).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from config.database import Base


# A primary-key type that autoincrements on both PostgreSQL (BigInteger) and
# SQLite (Integer). SQLite only auto-increments ``INTEGER PRIMARY KEY`` columns,
# so we use ``with_variant`` to switch dialects at DDL emission time.
_PkBigInt = BigInteger().with_variant(Integer(), "sqlite")


# --------------------------------------------------------------------------- helpers

def _now() -> datetime:
    """UTC-naive current time (PostgreSQL-friendly)."""
    return datetime.utcnow()


# --------------------------------------------------------------------------- Target

class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    scans: Mapped[List["Scan"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<Target(id={self.id}, domain={self.domain!r})>"


# --------------------------------------------------------------------------- Scan

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    output_dir: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")

    subdomains: Mapped[List["Subdomain"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    dns_records: Mapped[List["DnsRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    http_infos: Mapped[List["HttpInfo"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    cloud_assets: Mapped[List["CloudAsset"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    ip_addresses: Mapped[List["IpAddress"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    api_endpoints: Mapped[List["ApiEndpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_scans_target_started", "target_id", "started_at"),
    )


# --------------------------------------------------------------------------- Subdomain

class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_live_http: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="subdomains")

    dns_records: Mapped[List["DnsRecord"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )
    http_info: Mapped[Optional["HttpInfo"]] = relationship(
        back_populates="subdomain", uselist=False, cascade="all, delete-orphan"
    )
    cloud_asset: Mapped[Optional["CloudAsset"]] = relationship(
        back_populates="subdomain", uselist=False, cascade="all, delete-orphan"
    )
    ip_addresses: Mapped[List["IpAddress"]] = relationship(
        back_populates="subdomain", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_subdomains_scan_name", "scan_id", "name"),
    )


# --------------------------------------------------------------------------- DnsRecord

class DnsRecord(Base):
    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subdomain_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    record_type: Mapped[str] = mapped_column(String(8), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="dns_records")
    subdomain: Mapped[Subdomain] = relationship(back_populates="dns_records")

    __table_args__ = (
        Index("ix_dns_scan_sub_type", "scan_id", "subdomain_id", "record_type"),
    )


# --------------------------------------------------------------------------- HttpInfo

class HttpInfo(Base):
    __tablename__ = "http_information"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subdomain_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    final_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    server_header: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    content_length: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    redirect_chain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scheme: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    webserver: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tech_blob: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="http_infos")
    subdomain: Mapped[Subdomain] = relationship(back_populates="http_info")
    technologies: Mapped[List["Technology"]] = relationship(
        back_populates="http_info", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_http_scan_status", "scan_id", "status_code"),
    )


# --------------------------------------------------------------------------- CloudAsset

class CloudAsset(Base):
    __tablename__ = "cloud_assets"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subdomain_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("subdomains.id", ondelete="CASCADE"),
        nullable=False, unique=True, index=True,
    )
    provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cdn: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    waf: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_cloud_hosted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="cloud_assets")
    subdomain: Mapped[Subdomain] = relationship(back_populates="cloud_asset")


# --------------------------------------------------------------------------- IpAddress

class IpAddress(Base):
    __tablename__ = "ip_addresses"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subdomain_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("subdomains.id", ondelete="CASCADE"), nullable=False, index=True
    )
    address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    reverse_dns: Mapped[Optional[str]] = mapped_column(String(253), nullable=True)
    asn: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    asn_org: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    country: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    hosting_provider: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="ip_addresses")
    subdomain: Mapped[Subdomain] = relationship(back_populates="ip_addresses")
    ports: Mapped[List["Port"]] = relationship(
        back_populates="ip_address", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_ip_scan_addr", "scan_id", "address"),
    )


# --------------------------------------------------------------------------- Port

class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("ip_addresses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    ip_address: Mapped[IpAddress] = relationship(back_populates="ports")
    services: Mapped[List["Service"]] = relationship(
        back_populates="port", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_ports_scan_ip_port", "scan_id", "ip_address_id", "port"),
    )


# --------------------------------------------------------------------------- Service

class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    os: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    extra: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    port: Mapped[Port] = relationship(back_populates="services")


# --------------------------------------------------------------------------- Technology

class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    http_info_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("http_information.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    http_info: Mapped[HttpInfo] = relationship(back_populates="technologies")

    __table_args__ = (
        Index("ix_tech_scan_http", "scan_id", "http_info_id"),
    )


# --------------------------------------------------------------------------- ApiEndpoint

class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_host: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    method: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    body: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tag: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="api_endpoints")

    __table_args__ = (
        Index("ix_api_scan_host", "scan_id", "source_host"),
    )


# --------------------------------------------------------------------------- Vulnerability

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(_PkBigInt, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        _PkBigInt, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    template_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    matched_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    matched_at: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reference_urls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=_now, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="vulnerabilities")

    __table_args__ = (
        Index("ix_vuln_scan_severity", "scan_id", "severity"),
    )
