"""
scanners/dnsx.py — DNS resolution with dnsx
"""
from utils import run_cmd, safe_jsonl, find_bin

def scan(subdomains, timeout=120):
    """Run dnsx for DNS resolution."""
    print("  [3/7] dnsx...", end="", flush=True)
    binary = find_bin("dnsx")
    if not binary or not subdomains:
        print(" 0 records")
        return {"records": [], "resolved_count": 0}

    cmd = [binary, "-silent", "-json", "-a", "-aaaa", "-cname",
           "-mx", "-txt", "-ns", "-soa", "-t", "20", "-timeout", "10", "-retry", "1"]
    ok, stdout, stderr = run_cmd(cmd, timeout=timeout, stdin_text="\n".join(subdomains))

    records = []
    fmap = {"a": "A", "aaaa": "AAAA", "cname": "CNAME",
            "mx": "MX", "txt": "TXT", "ns": "NS", "soa": "SOA"}
    for rec in safe_jsonl(stdout):
        host = (rec.get("host") or rec.get("input") or "").strip().lower()
        if not host:
            continue
        for field, rtype in fmap.items():
            val = rec.get(field)
            if val is None:
                continue
            if isinstance(val, list):
                for v in val:
                    records.append({"host": host, "type": rtype, "value": str(v), "ttl": rec.get("ttl")})
            elif isinstance(val, dict):
                records.append({"host": host, "type": rtype, "value": str(val), "ttl": rec.get("ttl")})
            elif val:
                records.append({"host": host, "type": rtype, "value": str(val), "ttl": rec.get("ttl")})

    resolved = sorted({r["host"] for r in records})
    print(f" {len(resolved)} hosts, {len(records)} records")
    return {"records": records, "resolved_count": len(resolved)}
