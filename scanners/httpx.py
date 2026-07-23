"""
scanners/httpx.py — Live HTTP detection with PD httpx
"""
import subprocess
from utils import run_cmd, safe_jsonl, sanitize, find_bin

def scan(hosts, timeout=120):
    """Run httpx for live HTTP detection."""
    print("  [4/7] httpx...", end="", flush=True)
    binary = find_bin("httpx")
    if not binary:
        print(" NOT FOUND")
        return {"hosts": [], "count": 0}
    if not hosts:
        print(" 0 hosts")
        return {"hosts": [], "count": 0}

    hosts = hosts[:50]
    cmd = [binary, "-silent", "-json", "-status-code", "-title", "-server",
           "-content-length", "-tech-detect", "-ip", "-cname",
           "-timeout", "10", "-threads", "20", "-no-color", "-follow-redirects"]
    ok, stdout, stderr = run_cmd(cmd, timeout=timeout, stdin_text="\n".join(hosts))

    live = []
    for row in safe_jsonl(stdout):
        if row.get("failed") is True:
            continue
        url = row.get("url") or row.get("input") or ""
        if not url:
            continue
        host = row.get("host") or row.get("input") or ""
        ips = []
        for f in ("a", "aaaa"):
            v = row.get(f)
            if isinstance(v, list):
                ips.extend(v)
            elif isinstance(v, str) and v:
                ips.append(v)
        if row.get("host_ip") and row["host_ip"] not in ips:
            ips.append(row["host_ip"])

        live.append({
            "url": url, "host": host,
            "final_url": row.get("final_url") or url,
            "status_code": row.get("status_code") or row.get("status"),
            "title": sanitize(row.get("title"), 512),
            "webserver": sanitize(row.get("webserver"), 128),
            "technologies": row.get("tech") or row.get("technologies") or [],
            "ips": ips,
        })

    print(f" {len(live)} live hosts")
    return {"hosts": live, "count": len(live)}
