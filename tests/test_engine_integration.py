"""Integration test for the scan engine.

Mocks the external scanner subprocess calls (subfinder, dnsx, ...) so the
engine can be tested end-to-end without the tools being installed.

Uses the shared SQLite engine set up in ``tests/conftest.py``.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from database import models
from database.repository import Repository
from scanners.base import BaseScanner, ScanContext, ScanResult
from scanners.engine import ScanEngine


class _StubScanner(BaseScanner):
    """A stub scanner that returns a canned result without calling subprocesses."""

    name = "subfinder"
    description = "stub"
    required_tools: list[str] = []

    def __init__(self, ctx: ScanContext, result: ScanResult) -> None:
        # Bypass the normal init so we don't validate required_tools
        self.ctx = ctx
        self.log = MagicMock()
        self._result = result

    def run(self) -> ScanResult:
        return self._result


def _make_canned_result(subdomains):
    return ScanResult(
        scanner="subfinder", success=True, duration_seconds=0.1,
        data={"subdomains": subdomains, "count": len(subdomains)},
    )


class TestScanEngineIntegration:
    def test_subdomain_scan_with_mocked_scanner(self, fresh_db) -> None:
        """Replace the subfinder scanner with a stub and run end-to-end."""
        target_domain = "example.com"
        canned = _make_canned_result(["a.example.com", "b.example.com"])

        def _stub_factory(scan_type):
            """Return scanner classes that build _StubScanner instances."""
            class _Wrapper:
                name = "subfinder"
                description = "stub"
                required_tools: list[str] = []

                def __init__(self, ctx):
                    self._stub = _StubScanner(ctx, canned)

                def execute(self) -> ScanResult:
                    return self._stub.execute()

            return [_Wrapper]

        with patch("scanners.engine.get_scanner", side_effect=_stub_factory):
            engine = ScanEngine()
            outcome = engine.run(target=target_domain, scan_type="subdomain")

        assert outcome.success is True
        assert outcome.scan_type == "subdomain"
        assert outcome.target == target_domain

        # Database should now contain the target + scan + 2 subdomains
        targets = Repository.list_targets()
        target = next((t for t in targets if t.domain == target_domain), None)
        assert target is not None

        scans = Repository.list_scans_for_target(target.id, limit=5)
        assert len(scans) >= 1
        completed = [s for s in scans if s.status == "completed"]
        assert len(completed) >= 1

        # JSON output should exist
        assert os.path.isdir(outcome.output_dir)
        import pathlib
        full_json = pathlib.Path(outcome.output_dir) / "full_scan.json"
        assert full_json.exists()
        subdomains_json = pathlib.Path(outcome.output_dir) / "subdomains.json"
        assert subdomains_json.exists()

        # The changes.json file should also exist (even on first scan)
        changes_json = pathlib.Path(outcome.output_dir) / "changes.json"
        assert changes_json.exists()
