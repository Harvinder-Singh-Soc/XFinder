"""Integration tests for the database layer.

These tests use SQLite (in-memory) so they run anywhere without a real
PostgreSQL. The schema is the same; only the driver differs.

The engine is set up once in ``tests/conftest.py``.
"""

from __future__ import annotations

from database.repository import Repository


class TestRepository:
    def test_get_or_create_target(self, fresh_db) -> None:
        t1 = Repository.get_or_create_target("example.com")
        t2 = Repository.get_or_create_target("example.com")
        assert t1.id == t2.id
        assert t1.domain == "example.com"

    def test_scan_lifecycle(self, fresh_db) -> None:
        target = Repository.get_or_create_target("example.com")
        scan = Repository.start_scan(target.id, "subdomain", output_dir="/tmp")
        assert scan.status == "running"
        Repository.finish_scan(scan.id, status="completed")
        refreshed = Repository.get_scan(scan.id)
        assert refreshed.status == "completed"
        assert refreshed.duration_seconds is not None
        assert refreshed.finished_at is not None

    def test_bulk_insert_subdomains_dedup(self, fresh_db) -> None:
        target = Repository.get_or_create_target("example.com")
        scan = Repository.start_scan(target.id, "subdomain")
        # First insert
        n1 = Repository.bulk_insert_subdomains(
            scan.id, target.id, ["a.example.com", "b.example.com", "a.example.com"],
            source="subfinder",
        )
        assert n1 == 2  # deduped within the call
        # Second insert with overlap
        n2 = Repository.bulk_insert_subdomains(
            scan.id, target.id, ["a.example.com", "c.example.com"],
            source="subfinder",
        )
        assert n2 == 1  # 'a' already exists; only 'c' is new

    def test_vulnerability_roundtrip(self, fresh_db) -> None:
        target = Repository.get_or_create_target("example.com")
        scan = Repository.start_scan(target.id, "vulnerability")
        vulns = [
            {
                "template-id": "CVE-2024-1234",
                "info": {
                    "name": "Test CVE",
                    "severity": "high",
                    "description": "Test description",
                    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
                    "tags": ["cve", "rce"],
                },
                "matched-url": "https://example.com/admin",
            }
        ]
        n = Repository.bulk_insert_vulnerabilities(scan.id, vulns)
        assert n == 1

        summary = Repository.get_scan_summary(scan.id)
        assert len(summary["vulnerabilities"]) == 1
        v = summary["vulnerabilities"][0]
        assert v["template_id"] == "CVE-2024-1234"
        assert v["severity"] == "high"
        assert v["url"] == "https://example.com/admin"

    def test_get_previous_scan(self, fresh_db) -> None:
        target = Repository.get_or_create_target("example.com")
        s1 = Repository.start_scan(target.id, "full")
        Repository.finish_scan(s1.id, status="completed")
        s2 = Repository.start_scan(target.id, "full")
        Repository.finish_scan(s2.id, status="completed")
        s3 = Repository.start_scan(target.id, "full")  # still running

        prev = Repository.get_previous_scan(s3.id, target.id)
        assert prev is not None
        assert prev.id == s2.id

    def test_scan_summary_structure(self, fresh_db) -> None:
        target = Repository.get_or_create_target("example.com")
        scan = Repository.start_scan(target.id, "full")
        Repository.bulk_insert_subdomains(scan.id, target.id,
                                          ["a.example.com", "b.example.com"])
        summary = Repository.get_scan_summary(scan.id)
        assert "subdomains" in summary
        assert "dns" in summary
        assert "http" in summary
        assert "ports" in summary
        assert "vulnerabilities" in summary
        assert "api_endpoints" in summary
        assert sorted(summary["subdomains"]) == ["a.example.com", "b.example.com"]
