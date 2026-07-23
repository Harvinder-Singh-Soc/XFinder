"""
scanners/katana.py — Web crawling with Katana
"""
from utils import run_cmd, safe_jsonl, sanitize, find_bin

def scan(live_hosts, timeout=120):
    """Run Katana for web crawling."""
    print("  [7/7] Katana...", end="", flush=True)
    binary = find_bin("katana")
    if not binary:
        print(" NOT FOUND")
        return {"endpoints": [], "endpoint_count": 0}

    hosts = (live_hosts or [])[:10]
    if not hosts:
        print(" 0 endpoints")
        return {"endpoints": [], "endpoint_count": 0}

    endpoints = []
    for host in hosts:
        url = host if host.startswith("http") else f"https://{host}"
        cmd = [binary, "-u", url, "-silent", "-j", "-d", "2", "-c", "10",
               "-timeout", "5", "-retry", "1"]
        ok, stdout, stderr = run_cmd(cmd, timeout=30)
        for row in safe_jsonl(stdout):
            req = row.get("request", {})
            ep = (req.get("endpoint") if isinstance(req, dict) else None) or row.get("url")
            if ep:
                endpoints.append({
                    "source_host": host,
                    "method": req.get("method", "GET") if isinstance(req, dict) else "GET",
                    "url": sanitize(ep, 2048),
                })

    seen = set()
    deduped = []
    for ep in endpoints:
        k = (ep["source_host"], ep["method"], ep["url"])
        if k not in seen:
            seen.add(k)
            deduped.append(ep)

    print(f" {len(deduped)} endpoints")
    return {"endpoints": deduped, "endpoint_count": len(deduped)}
