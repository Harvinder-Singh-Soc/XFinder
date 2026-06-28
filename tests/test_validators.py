"""Unit tests for utils/validators.py."""

from __future__ import annotations

import pytest

from utils.validators import (
    extract_hostname_from_url,
    is_valid_domain,
    is_valid_ip,
    is_valid_url,
    normalize_domain,
)


class TestIsValidDomain:
    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "api.v2.example.co.uk",
        "EXAMPLE.COM",
        "  example.com  ",
        "example.com.",
    ])
    def test_valid(self, domain: str) -> None:
        assert is_valid_domain(domain) is True

    @pytest.mark.parametrize("domain", [
        "",
        None,
        "not_a_domain",
        "-bad.example.com",
        "bad-.example.com",
        "a" * 64 + ".example.com",   # label too long
        "example",
        "example.123",
    ])
    def test_invalid(self, domain: str) -> None:
        assert is_valid_domain(domain) is False


class TestIsValidIP:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "8.8.8.8",
        "::1",
        "2001:db8::1",
    ])
    def test_valid(self, ip: str) -> None:
        assert is_valid_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "",
        None,
        "not-an-ip",
        "999.999.999.999",
        "127.0.0",
    ])
    def test_invalid(self, ip: str) -> None:
        assert is_valid_ip(ip) is False


class TestIsValidURL:
    @pytest.mark.parametrize("url", [
        "http://example.com",
        "https://sub.example.com/path?q=1",
        "https://example.com:8443",
    ])
    def test_valid(self, url: str) -> None:
        assert is_valid_url(url) is True

    @pytest.mark.parametrize("url", [
        "",
        None,
        "example.com",
        "ftp://example.com",
    ])
    def test_invalid(self, url: str) -> None:
        assert is_valid_url(url) is False


def test_normalize_domain() -> None:
    assert normalize_domain("  Example.COM.  ") == "example.com"


def test_extract_hostname_from_url() -> None:
    assert extract_hostname_from_url("https://example.com:8443/path") == "example.com"
    assert extract_hostname_from_url("not-a-url") is None
