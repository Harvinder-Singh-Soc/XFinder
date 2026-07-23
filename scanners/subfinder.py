"""
scanners/subfinder.py — Subdomain enumeration with Subfinder
"""
from utils import run_cmd, sanitize, find_bin

def scan(target, timeout=180):
    """Run Subfinder for subdomain enumeration."""
    print("  [2/7] Subfinder...", end="", flush=True)
    binary = find_bin("subfinder")
    if not binary:
        subs = [target, f"www.{target}"]
        print(f" NOT FOUND — fallback ({len(subs)})")
        return {"subdomains": subs, "count": len(subs)}

    cmd = [binary, "-d", target, "-silent", "-recursive", "-timeout", "10", "-t", "20"]
    ok, stdout, stderr = run_cmd(cmd, timeout=timeout)
    subs = sorted({l.strip().lower() for l in stdout.splitlines()
                   if l.strip() and not l.startswith("[")})
    if not subs:
        subs = [target, f"www.{target}"]
        print(f" {len(subs)} (fallback)")
    else:
        print(f" {len(subs)} subdomains")
    return {"subdomains": subs, "count": len(subs)}
