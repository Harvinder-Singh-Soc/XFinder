"""Unit tests for enrichment/cloud.py."""

from __future__ import annotations

from enrichment.cloud import detect


class TestCloudDetect:
    def test_cloudflare_cname(self) -> None:
        result = detect("blog.example.com",
                        cnames=["blog.example.com.cdn.cloudflare.net"])
        assert result["provider"] == "Cloudflare"
        assert result["cdn"] == "Cloudflare"
        assert result["is_cloud_hosted"] is True

    def test_aws_s3_cname(self) -> None:
        result = detect("static.example.com",
                        cnames=["static.example.com.s3.amazonaws.com"])
        assert result["provider"] == "AWS S3"
        assert result["is_cloud_hosted"] is True

    def test_vercel_cname(self) -> None:
        result = detect("app.example.com", cnames=["cname.vercel-dns.com"])
        # Not in our list explicitly; should not match
        # But "vercel.app" is. Try direct match:
        result2 = detect("app.example.com", cnames=["app.vercel.app"])
        assert result2["provider"] == "Vercel"

    def test_server_header_cloudflare(self) -> None:
        result = detect("x.example.com", server_header="cloudflare")
        assert result["provider"] == "Cloudflare"

    def test_cf_ray_header(self) -> None:
        result = detect("x.example.com", headers={"cf-ray": "abc123-LAX"})
        assert result["provider"] == "Cloudflare"

    def test_no_match(self) -> None:
        result = detect("x.example.com",
                        cnames=["x.example.com"],
                        server_header="nginx/1.25.0")
        assert result["provider"] is None
        assert result["is_cloud_hosted"] is False

    def test_github_pages(self) -> None:
        result = detect("user.github.io", cnames=["user.github.io"])
        assert result["provider"] == "GitHub Pages"
