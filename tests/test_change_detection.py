"""Unit tests for reports/json_export.py — change detection logic."""

from __future__ import annotations

from reports.json_export import JsonExporter


def _build_summary(subdomains=None, ports=None, dns=None, cloud=None,
                   techs=None, vulns=None, api=None):
    return {
        "subdomains": subdomains or [],
        "ports": ports or [],
        "dns": dns or [],
        "cloud": cloud or [],
        "technologies": techs or [],
        "vulnerabilities": vulns or [],
        "api_endpoints": api or [],
    }


class TestChangeDetection:
    def test_first_scan_returns_empty_changes(self) -> None:
        changes = JsonExporter.compute_changes(
            previous=_build_summary(),
            current=_build_summary(subdomains=["a.example.com"]),
        )
        # First-scan pattern: everything is "new"
        assert changes["new_subdomains"] == ["a.example.com"]
        assert changes["removed_subdomains"] == []
        assert changes["summary"]["new_subdomains"] == 1

    def test_subdomain_changes(self) -> None:
        prev = _build_summary(subdomains=["a.example.com", "b.example.com"])
        curr = _build_summary(subdomains=["b.example.com", "c.example.com"])
        changes = JsonExporter.compute_changes(prev, curr)
        assert changes["new_subdomains"] == ["c.example.com"]
        assert changes["removed_subdomains"] == ["a.example.com"]

    def test_port_changes(self) -> None:
        prev = _build_summary(ports=[
            {"ip_id": 1, "port": 80, "proto": "tcp"},
            {"ip_id": 1, "port": 443, "proto": "tcp"},
        ])
        curr = _build_summary(ports=[
            {"ip_id": 1, "port": 443, "proto": "tcp"},
            {"ip_id": 1, "port": 8080, "proto": "tcp"},
        ])
        changes = JsonExporter.compute_changes(prev, curr)
        assert len(changes["new_ports"]) == 1
        assert changes["new_ports"][0] == [1, 8080, "tcp"]
        assert len(changes["closed_ports"]) == 1
        assert changes["closed_ports"][0] == [1, 80, "tcp"]

    def test_vulnerability_changes(self) -> None:
        prev = _build_summary(vulns=[
            {"template_id": "CVE-2024-0001", "url": "https://x.example.com/"},
            {"template_id": "CVE-2024-0002", "url": "https://y.example.com/"},
        ])
        curr = _build_summary(vulns=[
            {"template_id": "CVE-2024-0002", "url": "https://y.example.com/"},
            {"template_id": "CVE-2024-0003", "url": "https://z.example.com/"},
        ])
        changes = JsonExporter.compute_changes(prev, curr)
        assert changes["new_vulnerabilities"] == [["CVE-2024-0003", "https://z.example.com/"]]
        assert changes["resolved_vulnerabilities"] == [["CVE-2024-0001", "https://x.example.com/"]]

    def test_dns_changes(self) -> None:
        prev = _build_summary(dns=[
            {"subdomain_id": 1, "type": "A", "value": "1.2.3.4"},
        ])
        curr = _build_summary(dns=[
            {"subdomain_id": 1, "type": "A", "value": "1.2.3.5"},
            {"subdomain_id": 1, "type": "AAAA", "value": "::1"},
        ])
        changes = JsonExporter.compute_changes(prev, curr)
        assert len(changes["dns_changes"]) == 1
        diff = changes["dns_changes"][0]
        assert diff["subdomain_id"] == 1
        # The old A record (1.2.3.4) should be in removed
        assert {"type": "A", "value": "1.2.3.4"} in diff["removed"]
        # The new A record (1.2.3.5) and AAAA (::1) should be in added
        assert {"type": "A", "value": "1.2.3.5"} in diff["added"]
        assert {"type": "AAAA", "value": "::1"} in diff["added"]

    def test_cloud_changes(self) -> None:
        prev = _build_summary(cloud=[
            {"subdomain_id": 1, "provider": "Cloudflare", "cdn": "Cloudflare", "waf": "Cloudflare"},
        ])
        curr = _build_summary(cloud=[
            {"subdomain_id": 1, "provider": "AWS CloudFront", "cdn": "AWS CloudFront", "waf": None},
        ])
        changes = JsonExporter.compute_changes(prev, curr)
        assert len(changes["cloud_changes"]) == 1
        assert changes["cloud_changes"][0]["previous"]["provider"] == "Cloudflare"
        assert changes["cloud_changes"][0]["current"]["provider"] == "AWS CloudFront"

    def test_api_endpoint_changes(self) -> None:
        prev = _build_summary(api=["https://x.example.com/api/v1", "https://x.example.com/login"])
        curr = _build_summary(api=["https://x.example.com/api/v2", "https://x.example.com/login"])
        changes = JsonExporter.compute_changes(prev, curr)
        assert changes["new_api_endpoints"] == ["https://x.example.com/api/v2"]
        assert changes["removed_api_endpoints"] == ["https://x.example.com/api/v1"]

    def test_summary_counts(self) -> None:
        prev = _build_summary(subdomains=["a"])
        curr = _build_summary(subdomains=["a", "b"])
        changes = JsonExporter.compute_changes(prev, curr)
        s = changes["summary"]
        assert s["new_subdomains"] == 1
        assert s["removed_subdomains"] == 0
        assert s["new_ports"] == 0
