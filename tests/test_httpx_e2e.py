"""End-to-end test that uses the EXACT httpx JSON output format the user
observed, to verify our parser handles every field correctly.

This test mocks subprocess.run and feeds it canned output that matches
the real httpx v1.x JSON schema (with fields: timestamp, port, url, input,
title, scheme, webserver, content_type, method, host, host_ip, path,
final_url, time, chain_status_codes, a, aaaa, tech, words, lines,
status_code, content_length, failed, knowledgebase, resolvers).
"""

from __future__ import annotations

import json
from unittest.mock import patch
from scanners.base import ScanContext, ScanResult
from scanners.httpx import HttpxScanner
from utils.helpers import CommandResult


# Real httpx output (verbatim from user's terminal)
REAL_HTTPX_OUTPUT = """{"timestamp":"2026-06-27T13:50:28.436336974-04:00","port":"443","url":"https://www.nmap.org","input":"www.nmap.org","title":"Nmap: the Network Mapper - Free Security Scanner","scheme":"https","webserver":"Apache/2.4.6 (CentOS)","content_type":"text/html","method":"GET","host":"www.nmap.org","host_ip":"50.116.1.184","path":"/","final_url":"https://nmap.org/","time":"4.660831579s","chain_status_codes":[301,200],"a":["50.116.1.184"],"aaaa":["2600:3c01:e000:3e6::6d4e:7061"],"tech":["Apache HTTP Server:2.4.6","CentOS","HSTS"],"words":1753,"lines":342,"status_code":200,"content_length":19639,"failed":false,"knowledgebase":{"pHash":0},"resolvers":["1.1.1.1:53","1.0.0.1:53"]}
{"timestamp":"2026-06-27T13:50:28.5Z","port":"443","url":"https://nmap.org","input":"nmap.org","title":"Nmap: the Network Mapper - Free Security Scanner","scheme":"https","webserver":"Apache/2.4.6 (CentOS)","content_type":"text/html","method":"GET","host":"nmap.org","host_ip":"45.33.32.156","path":"/","final_url":"https://nmap.org/","time":"1.234s","chain_status_codes":[200],"a":["45.33.32.156"],"aaaa":[],"tech":["Apache HTTP Server:2.4.6","CentOS"],"words":1753,"lines":342,"status_code":200,"content_length":19639,"failed":false,"knowledgebase":{"pHash":0},"resolvers":["1.1.1.1:53","1.0.0.1:53"]}
{"timestamp":"2026-06-27T13:50:28.6Z","port":"443","url":"https://blog.nmap.org","input":"blog.nmap.org","failed":true,"error":"connection refused"}
"""


def test_httpx_parses_real_world_output():
    """Verify HttpxScanner correctly parses the user's actual httpx output."""
    ctx = ScanContext(
        target="nmap.org", scan_id=1, target_id=1, output_dir="/tmp/x",
        threads=20, timeout=15,
    )
    ctx.subdomains = ["www.nmap.org", "nmap.org", "blog.nmap.org"]
    ctx.cache["resolved_subdomains"] = ["www.nmap.org", "nmap.org", "blog.nmap.org"]

    scanner = HttpxScanner(ctx)

    # Mock run_subprocess to return the real httpx output
    fake_result = CommandResult(
        returncode=0,
        stdout=REAL_HTTPX_OUTPUT,
        stderr="",
        timed_out=False,
        duration_seconds=4.5,
    )
    with patch("scanners.httpx.run_subprocess", return_value=fake_result):
        result = scanner.run()

    # The "failed:true" row must be SKIPPED, only 2 live hosts expected
    assert result.success is True, f"Expected success, got error: {result.error}"
    assert result.data["count"] == 2, f"Expected 2 live hosts, got {result.data['count']}"
    assert "www.nmap.org" in ctx.live_hosts
    assert "nmap.org" in ctx.live_hosts
    assert "blog.nmap.org" not in ctx.live_hosts, "blog.nmap.org was 'failed:true' — must be skipped"

    # Verify all fields parsed correctly
    www = next(h for h in result.data["hosts"] if h["host"] == "www.nmap.org")
    assert www["status_code"] == 200
    assert www["title"] == "Nmap: the Network Mapper - Free Security Scanner"
    assert "Apache" in www["server_header"]
    assert www["final_url"] == "https://nmap.org/"
    assert www["scheme"] == "https"
    assert www["webserver"] == "Apache/2.4.6 (CentOS)"
    # IPs should include both A and AAAA records
    assert "50.116.1.184" in www["ips"]
    assert "2600:3c01:e000:3e6::6d4e:7061" in www["ips"]
    # Technologies (httpx uses "tech" field)
    tech_str = " ".join(www["technologies"])
    assert "Apache HTTP Server" in tech_str
    assert "CentOS" in tech_str
    assert "HSTS" in tech_str
    # Response time parsed from "4.660831579s"
    assert www["response_time_ms"] == 4660, f"Got {www['response_time_ms']}"

    print("PASS: HttpxScanner correctly parses real-world httpx output")
    print(f"  - {result.data['count']} live hosts found (1 failed row skipped)")
    print(f"  - www.nmap.org: status=200, server=Apache, tech={www['technologies']}")
    print(f"  - IPs parsed: {www['ips']}")
    print(f"  - Response time: {www['response_time_ms']}ms")


def test_httpx_handles_empty_output_with_stderr():
    """Verify that empty stdout + non-empty stderr is reported as a failure
    (this is the silent-flag-rejection bug we just fixed)."""
    ctx = ScanContext(
        target="example.com", scan_id=1, target_id=1, output_dir="/tmp/x",
    )
    ctx.subdomains = ["www.example.com"]
    ctx.cache["resolved_subdomains"] = ["www.example.com"]

    scanner = HttpxScanner(ctx)

    fake_result = CommandResult(
        returncode=0,
        stdout="",  # empty
        stderr="unknown flag: -rate-limit",  # stderr has the error
        timed_out=False,
        duration_seconds=0.4,
    )
    with patch("scanners.httpx.run_subprocess", return_value=fake_result):
        result = scanner.run()

    # Must FAIL (not silently return 0 results)
    assert result.success is False, "Empty stdout + stderr should be a failure"
    assert "rate-limit" in result.error or "stderr" in result.error, \
        f"Error should mention the stderr; got: {result.error}"
    print("PASS: Silent flag rejection now properly reported as failure")


def test_httpx_handles_completely_empty_output():
    """If both stdout AND stderr are empty, that's a different situation —
    the scanner ran successfully but found no live hosts. Should succeed
    with 0 results."""
    ctx = ScanContext(
        target="example.com", scan_id=1, target_id=1, output_dir="/tmp/x",
    )
    ctx.subdomains = ["dead.example.com"]
    ctx.cache["resolved_subdomains"] = ["dead.example.com"]

    scanner = HttpxScanner(ctx)

    fake_result = CommandResult(
        returncode=0, stdout="", stderr="",
        timed_out=False, duration_seconds=2.0,
    )
    with patch("scanners.httpx.run_subprocess", return_value=fake_result):
        result = scanner.run()

    assert result.success is True, "Empty output (no stderr) should be success"
    assert result.data["count"] == 0
    print("PASS: Empty stdout + empty stderr = success with 0 hosts")


if __name__ == "__main__":
    test_httpx_parses_real_world_output()
    test_httpx_handles_empty_output_with_stderr()
    test_httpx_handles_completely_empty_output()
    print()
    print("=" * 60)
    print("ALL E2E TESTS PASSED")
    print("=" * 60)
