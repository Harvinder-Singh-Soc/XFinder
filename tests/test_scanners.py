"""Unit tests for scanners/base.py and registry."""

from __future__ import annotations

import pytest

from scanners.base import BaseScanner, ScanContext, ScanResult
from scanners.registry import SCANNERS, SCAN_LABELS, get_scanner, list_scan_types
from scanners.subfinder import SubfinderScanner
from scanners.dnsx import DnsxScanner
from scanners.httpx import HttpxScanner
from scanners.naabu import NaabuScanner
from scanners.nmap import NmapScanner
from scanners.katana import KatanaScanner
from scanners.nuclei import NucleiScanner


def test_scan_types_registered() -> None:
    types = list_scan_types()
    assert "subdomain" in types
    assert "dns" in types
    assert "cloud" in types
    assert "port" in types
    assert "webapi" in types
    assert "vulnerability" in types
    assert "full" in types


def test_full_scan_includes_all_scanners() -> None:
    full_chain = get_scanner("full")
    assert SubfinderScanner in full_chain
    assert DnsxScanner in full_chain
    assert HttpxScanner in full_chain
    assert NaabuScanner in full_chain
    assert NmapScanner in full_chain
    assert KatanaScanner in full_chain
    assert NucleiScanner in full_chain


def test_dns_chain_starts_with_subfinder() -> None:
    """dnsx requires subdomains → subfinder must run first."""
    chain = get_scanner("dns")
    assert chain[0] is SubfinderScanner
    assert chain[-1] is DnsxScanner


def test_full_scan_order_matches_workflow() -> None:
    """Order should be: subfinder → dnsx → httpx → naabu → nmap → katana → nuclei."""
    chain = get_scanner("full")
    expected = [SubfinderScanner, DnsxScanner, HttpxScanner,
                NaabuScanner, NmapScanner, KatanaScanner, NucleiScanner]
    assert chain == expected


def test_unknown_scan_type_raises() -> None:
    with pytest.raises(KeyError):
        get_scanner("nonexistent")


def test_scan_labels_complete() -> None:
    for st in list_scan_types():
        assert st in SCAN_LABELS


class TestBaseScanner:
    def test_check_tools_returns_missing(self) -> None:
        """SubfinderScanner requires the 'subfinder' binary; if absent, it's reported."""
        # We can't guarantee presence/absence in the test env, but the
        # method should always return a list (possibly empty).
        result = SubfinderScanner.check_tools()
        assert isinstance(result, list)

    def test_execute_returns_scan_result(self, monkeypatch) -> None:
        """Stub a scanner's run() to verify execute() lifecycle."""
        class _Stub(BaseScanner):
            name = "stub"
            description = "stub"
            required_tools = []

            def run(self) -> ScanResult:
                return ScanResult(scanner="stub", success=True, duration_seconds=0.0,
                                  data={"hello": "world"})

        ctx = ScanContext(target="example.com", scan_id=1, target_id=1,
                          output_dir="/tmp")
        result = _Stub(ctx).execute()
        assert result.success is True
        assert result.data == {"hello": "world"}
        assert result.duration_seconds >= 0.0

    def test_execute_catches_exception(self) -> None:
        class _Crashing(BaseScanner):
            name = "crash"
            description = "crash"
            required_tools = []

            def run(self) -> ScanResult:
                raise RuntimeError("boom")

        ctx = ScanContext(target="example.com", scan_id=1, target_id=1,
                          output_dir="/tmp")
        result = _Crashing(ctx).execute()
        assert result.success is False
        assert "boom" in (result.error or "")

    def test_execute_reports_missing_tool(self) -> None:
        class _NeedsGhost(BaseScanner):
            name = "ghost"
            description = "ghost"
            required_tools = ["definitely_not_a_real_binary_xyz123"]

            def run(self) -> ScanResult:  # pragma: no cover - never reached
                return ScanResult(scanner="ghost", success=True, duration_seconds=0.0)

        ctx = ScanContext(target="example.com", scan_id=1, target_id=1,
                          output_dir="/tmp")
        result = _NeedsGhost(ctx).execute()
        assert result.success is False
        assert "definitely_not_a_real_binary_xyz123" in (result.error or "")
