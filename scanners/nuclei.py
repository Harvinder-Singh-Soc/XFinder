"""
scanners/nuclei.py — Vulnerability scanning with Nuclei
"""
import os, json, re
from utils import run_cmd, safe_jsonl, sanitize, find_bin

def scan(target, live_hosts=None, timeout=180):
    """Run Nuclei vulnerability scan."""
    print("  [1/7] Nuclei...", end="", flush=True)
    binary = find_bin("nuclei")
    if not binary:
        print(" NOT FOUND — skipping")
        return {"vulnerabilities": [], "count": 0}

    targets = live_hosts[:5] if live_hosts else [
        f"https://{target}", f"http://{target}", f"https://www.{target}"
    ]
    cmd = [binary, "-silent", "-j", "-duc", "-nc", "-c", "10",
           "-timeout", "5", "-retries", "1", "-rl", "50",
           "-severity", "info,low,medium,high,critical"]

    tdir = os.path.expanduser("~/nuclei-templates")
    if os.path.isdir(tdir):
        cmd.extend(["-t", tdir])

    ok, stdout, stderr = run_cmd(cmd, timeout=timeout, stdin_text="\n".join(targets))
    findings = safe_jsonl(stdout)
    results = []
    for f in findings:
        info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        results.append({
            "template_id": sanitize(f.get("template-id") or f.get("template", "unknown"), 128),
            "name": sanitize(info.get("name", "Unknown"), 512),
            "severity": sanitize(info.get("severity", "info"), 16),
            "description": sanitize(info.get("description"), 10000),
            "matched_url": sanitize(f.get("matched-url") or f.get("matched-at") or f.get("url"), 2048),
            "evidence": sanitize(f.get("extracted-results"), 10000),
            "cvss_score": (info.get("classification", {}).get("cvss-score")
                           if isinstance(info.get("classification"), dict) else None),
        })
    print(f" {len(results)} findings")
    return {"vulnerabilities": results, "count": len(results)}
