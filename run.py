#!/usr/bin/env python3
"""
XFinder-CTEM Integrated Scanner
================================
Team 1 (Scanner) + Team 2 (CTEM Database) in one package.

Scans a target with 7 tools → Auto-syncs results to CTEM Supabase.

Usage:
    pip install supabase
    python run.py --target hackerone.com
    python run.py --target hackerone.com --no-sync
    python run.py                    # interactive mode

Scanners (in order):
    1. Nuclei    — Vulnerability scanning (runs FIRST)
    2. Subfinder — Subdomain enumeration
    3. dnsx      — DNS resolution
    4. httpx     — Live HTTP detection
    5. Naabu     — Port discovery
    6. Nmap      — Service detection
    7. Katana    — Web crawling

Enrichment (optional, needs API keys):
    - Shodan     — IP intelligence
    - VirusTotal — Domain reputation
"""
import argparse, json, os, sys, time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Import scanners
from scanners import nuclei, subfinder, dnsx, httpx, naabu, nmap, katana
from utils import find_bin

# ── CTEM Supabase Config ─────────────────────────────────────────────────────
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://eqlolqdgviakidyinwrt.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "sb_publishable_bvXFa9QnkBIC7ZYNbY_bUw_VN5shl4z")

# Enrichment API Keys (optional)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)


def ts():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def now_iso():
    return datetime.now().isoformat()


# ── Enrichment: Shodan ───────────────────────────────────────────────────────
def enrich_shodan(ip):
    """Get Shodan data for an IP (needs SHODAN_API_KEY)."""
    if not SHODAN_API_KEY:
        return None
    import urllib.request, urllib.error
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "asn": data.get("asn"),
                    "org": data.get("org"),
                    "country": data.get("country_name"),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                }
    except:
        pass
    return None


# ── Enrichment: VirusTotal ──────────────────────────────────────────────────
def enrich_virustotal(domain):
    """Get VirusTotal reputation for a domain (needs VIRUSTOTAL_API_KEY)."""
    if not VIRUSTOTAL_API_KEY:
        return None
    import urllib.request, urllib.error
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = urllib.request.Request(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "reputation": attrs.get("reputation"),
                    "malicious": stats.get("malicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "suspicious": stats.get("suspicious", 0),
                }
    except:
        pass
    return None


# ── CTEM Supabase Sync ───────────────────────────────────────────────────────
class CTEMSync:
    """Sync scan results to CTEM Supabase database."""

    def __init__(self):
        from supabase import create_client
        self.db = create_client(SUPABASE_URL, SUPABASE_KEY)
        self.ip_to_asset = {}

    def _next_id(self):
        try:
            r = self.db.table("assets").select("asset_id").order("asset_id", desc=True).limit(1).execute()
            if r.data:
                return r.data[0]["asset_id"] + 1
        except:
            pass
        return 1

    def sync_all(self, target, results, duration):
        print(f"\n{'─' * 55}")
        print(f"  Syncing to CTEM Supabase...")
        print(f"{'─' * 55}")

        # 1. Scan record
        nuclei_data = results.get("nuclei", {})
        by_sev = {}
        for v in nuclei_data.get("vulnerabilities", []):
            s = (v.get("severity") or "unknown").lower()
            by_sev[s] = by_sev.get(s, 0) + 1

        scan_data = {
            "scan_name": f"XFinder-{target}-{ts()}",
            "scan_type": "full", "scanner_tool": "XFinder", "scanner_version": "1.0",
            "initiated_by": "manual", "target_range": target,
            "assets_scanned": results.get("subfinder", {}).get("count", 0),
            "total_findings": nuclei_data.get("count", 0),
            "critical_findings": by_sev.get("critical", 0),
            "high_findings": by_sev.get("high", 0),
            "medium_findings": by_sev.get("medium", 0),
            "low_findings": by_sev.get("low", 0),
            "scan_started_at": now_iso(), "scan_finished_at": now_iso(),
            "duration_seconds": int(duration), "status": "completed",
        }
        try:
            self.db.table("scans").insert(scan_data).execute()
            print("  ✓ Scan record created")
        except Exception as e:
            print(f"  ✗ Scan record: {e}")

        # 2. Assets
        subs = results.get("subfinder", {}).get("subdomains", [])
        http_hosts = {h["host"]: h for h in results.get("httpx", {}).get("hosts", [])}
        next_id = self._next_id()
        created = 0
        print(f"  Syncing {len(subs)} assets...", end="", flush=True)
        for sub in subs:
            hi = http_hosts.get(sub, {})
            ad = {
                "asset_id": next_id, "asset_name": sub[:150],
                "asset_type": "server", "hostname": sub[:150], "fqdn": sub[:255],
                "environment": "production", "criticality": "medium",
                "status": "active" if hi else "inactive",
            }
            if hi.get("ips"):
                for ip in hi["ips"]:
                    if ":" not in ip:
                        ad["ip_address"] = ip
                        break
            techs = hi.get("technologies", [])
            for t in techs:
                tl = str(t).lower()
                if "cloudflare" in tl:
                    ad["cloud_provider"] = "cloudflare"
                    ad["network_zone"] = "cloud_vpc"
                    break
                elif "aws" in tl or "amazon" in tl:
                    ad["cloud_provider"] = "aws"
                    ad["network_zone"] = "cloud_vpc"
                    break
            if techs:
                ad["installed_software"] = json.dumps([{"name": str(t)[:128]} for t in techs])
            try:
                ex = self.db.table("assets").select("asset_id").eq("asset_id", next_id).execute()
                if ex.data:
                    self.db.table("assets").update(ad).eq("asset_id", next_id).execute()
                else:
                    self.db.table("assets").insert(ad).execute()
                if hi.get("ips"):
                    for ip in hi["ips"]:
                        if ":" not in ip:
                            self.ip_to_asset[ip] = next_id
                created += 1
            except:
                pass
            next_id += 1
        print(f" {created}/{len(subs)} synced")

        # 3. DNS
        records = results.get("dnsx", {}).get("records", [])
        created = 0
        print(f"  Syncing {len(records)} DNS records...", end="", flush=True)
        for rec in records:
            host = rec.get("host", "")
            parts = host.strip(".").split(".")
            rd = ".".join(parts[-2:]) if len(parts) > 2 else host
            sd = host[:-(len(rd) + 1)] if host != rd else None
            dd = {
                "domain": rd[:255], "subdomain": sd[:255] if sd else None,
                "fqdn": host[:255], "record_type": rec.get("type", "").upper(),
                "record_value": str(rec.get("value", ""))[:10000], "ttl": rec.get("ttl"),
                "is_internal": False, "status": "active",
            }
            try:
                self.db.table("dns_records").upsert(dd, on_conflict="domain,subdomain,record_type,record_value").execute()
                created += 1
            except:
                pass
        print(f" {created}/{len(records)} synced")

        # 4. Ports
        ports = results.get("naabu", {}).get("open_ports", [])
        svcs = {(s["ip"], s["port"]): s for s in results.get("nmap", {}).get("services", [])}
        created = 0; skipped = 0
        print(f"  Syncing {len(ports)} ports...", end="", flush=True)
        for pr in ports:
            ip = pr.get("ip"); pn = pr.get("port"); aid = self.ip_to_asset.get(ip)
            if not aid:
                skipped += 1
                continue
            svc = svcs.get((ip, pn), {})
            rl = "medium" if pn in (22, 3389, 5900) else ("high" if pn in (21, 23, 445, 1433, 3306, 5432, 6379, 27017) else "low")
            pd = {
                "asset_id": aid, "port_number": pn,
                "protocol": pr.get("protocol", "tcp").upper(), "state": "open",
                "service_name": (svc.get("name") or "")[:80],
                "service_version": (svc.get("version") or "")[:150],
                "service_product": (svc.get("product") or "")[:150],
                "is_expected": True, "risk_level": rl,
            }
            try:
                self.db.table("open_ports").upsert(pd, on_conflict="asset_id,port_number,protocol").execute()
                created += 1
            except:
                pass
        print(f" {created}/{len(ports)} synced ({skipped} skipped)")

        # 5. Vulnerabilities
        vulns = results.get("nuclei", {}).get("vulnerabilities", [])
        created = 0
        print(f"  Syncing {len(vulns)} vulnerabilities...", end="", flush=True)
        for v in vulns:
            vd = {
                "cve_id": (v.get("template_id", "unknown"))[:25],
                "title": (v.get("name", "Unknown"))[:300],
                "description": (v.get("description") or "")[:10000],
                "cvss_score": v.get("cvss_score"),
                "severity": (v.get("severity", "info"))[:20],
                "exploit_available": bool(v.get("evidence")),
                "fix_available": False,
            }
            try:
                self.db.table("vulnerabilities").upsert(vd, on_conflict="cve_id").execute()
                created += 1
            except:
                pass
        print(f" {created}/{len(vulns)} synced")
        print(f"\n  ✓ CTEM sync complete! Dashboard updated.")


# ── Main Scan Runner ─────────────────────────────────────────────────────────
def run_scan(target, sync=True):
    target = target.strip().lower().rstrip(".")
    print(f"\n{'=' * 55}")
    print(f"  XFinder-CTEM Scan: {target}")
    print(f"{'=' * 55}")
    print(f"  Time: {now_iso()}")
    print(f"  Sync: {'Yes → ' + SUPABASE_URL[:40] + '...' if sync else 'No (local only)'}")
    if SHODAN_API_KEY:
        print(f"  Shodan: Enabled")
    if VIRUSTOTAL_API_KEY:
        print(f"  VirusTotal: Enabled")

    print(f"\n  Tools:")
    for t in ["nuclei", "subfinder", "dnsx", "httpx", "naabu", "nmap", "katana"]:
        path = find_bin(t)
        print(f"    {'✓' if path else '✗'} {t}")

    start = time.time()
    results = {}
    live_hosts = []

    try:
        # 1. Nuclei (runs first on target directly)
        results["nuclei"] = nuclei.scan(target)

        # 2. Subfinder
        sf = subfinder.scan(target)
        results["subfinder"] = sf

        # 3. dnsx
        dns = dnsx.scan(sf["subdomains"])
        results["dnsx"] = dns

        # 4. httpx
        resolved = sorted(set(r["host"] for r in dns["records"])) if dns["records"] else sf["subdomains"]
        hp = httpx.scan(resolved)
        results["httpx"] = hp
        live_hosts = [h["host"] for h in hp["hosts"] if h.get("host")]

        # Re-run nuclei with live hosts if first run found nothing
        if live_hosts and results["nuclei"]["count"] == 0:
            print("  [+] Re-running Nuclei with live hosts...")
            results["nuclei"] = nuclei.scan(target, live_hosts)

        # 5. Naabu
        results["naabu"] = naabu.scan(live_hosts)

        # 6. Nmap
        results["nmap"] = nmap.scan(results["naabu"]["open_ports"])

        # 7. Katana
        results["katana"] = katana.scan(live_hosts)

    except Exception as e:
        print(f"\n  ✗ Error: {e}")

    duration = time.time() - start

    # Save JSON locally
    out = OUTPUT_DIR / target / ts()
    out.mkdir(parents=True, exist_ok=True)
    for name, data in results.items():
        (out / f"{name}.json").write_text(
            json.dumps({"target": target, "data": data}, indent=2, default=str))

    # Summary
    print(f"\n{'─' * 55}")
    print(f"  Done in {duration:.1f}s | Output: {out}")
    print(f"{'─' * 55}")
    print(f"  Subdomains:      {results.get('subfinder', {}).get('count', 0)}")
    print(f"  DNS records:     {len(results.get('dnsx', {}).get('records', []))}")
    print(f"  Live hosts:      {results.get('httpx', {}).get('count', 0)}")
    print(f"  Open ports:      {results.get('naabu', {}).get('port_count', 0)}")
    print(f"  Services:        {results.get('nmap', {}).get('service_count', 0)}")
    print(f"  Endpoints:       {results.get('katana', {}).get('endpoint_count', 0)}")
    print(f"  Vulnerabilities: {results.get('nuclei', {}).get('count', 0)}")

    # Sync to CTEM Supabase
    if sync:
        try:
            CTEMSync().sync_all(target, results, duration)
        except ImportError:
            print("\n  ✗ Install supabase: pip install supabase")
        except Exception as e:
            print(f"\n  ✗ Sync error: {e}")

    print(f"\n{'=' * 55}")
    print(f"  ALL DONE!")
    print(f"{'=' * 55}\n")
    return results


def main():
    parser = argparse.ArgumentParser(description="XFinder-CTEM Integrated Scanner")
    parser.add_argument("--target", "-t", help="Target domain to scan")
    parser.add_argument("--no-sync", action="store_true", help="Skip Supabase sync")
    args = parser.parse_args()

    if args.target:
        run_scan(args.target, sync=not args.no_sync)
    else:
        print(f"{'=' * 55}")
        print(f"  XFinder-CTEM Integrated Scanner")
        print(f"  Scan → Auto-Sync to CTEM Supabase")
        print(f"{'=' * 55}")
        print(f"  Supabase: {SUPABASE_URL[:40]}...")
        if SHODAN_API_KEY:
            print(f"  Shodan: Enabled")
        if VIRUSTOTAL_API_KEY:
            print(f"  VirusTotal: Enabled")
        while True:
            t = input("\n  Target domain (or 'exit'): ").strip()
            if t.lower() in ("exit", "quit", "q"):
                break
            if not t:
                continue
            s = input("  Sync to Supabase? [Y/n]: ").strip().lower()
            try:
                run_scan(t, sync=s != "n")
            except KeyboardInterrupt:
                print("\n  Interrupted.")
            except Exception as e:
                print(f"\n  Error: {e}")


if __name__ == "__main__":
    main()
