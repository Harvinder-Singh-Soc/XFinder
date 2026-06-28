# XFinder – User Guide

This guide walks through everything you need to use XFinder effectively in a real-world security operations workflow.

## Table of Contents

1. [First-Time Setup](#1-first-time-setup)
2. [Running Your First Scan](#2-running-your-first-scan)
3. [Understanding the Output](#3-understanding-the-output)
4. [Scheduling Recurring Scans](#4-scheduling-recurring-scans)
5. [Reviewing Scan History](#5-reviewing-scan-history)
6. [Working with JSON Reports](#6-working-with-json-reports)
7. [Configuring Performance](#7-configuring-performance)
8. [Using Enrichment APIs](#8-using-enrichment-apis)
9. [Operating in Production](#9-operating-in-production)

---

## 1. First-Time Setup

### Step 1 – Install Python and PostgreSQL

```bash
sudo apt-get update
sudo apt-get install -y python3.13 python3.13-venv postgresql postgresql-contrib
```

### Step 2 – Install External Tools

XFinder wraps the ProjectDiscovery suite. Install Go first, then the tools:

```bash
sudo apt-get install -y golang-go nmap
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Download Nuclei templates
nuclei -update-templates
```

### Step 3 – Set Up the Database

```bash
sudo -u postgres psql <<EOF
CREATE USER xfinder WITH PASSWORD 'your_secure_password';
CREATE DATABASE xfinder OWNER xfinder;
GRANT ALL PRIVILEGES ON DATABASE xfinder TO xfinder;
-- IMPORTANT (PostgreSQL 15+): the public schema no longer grants CREATE
-- to non-superusers by default. Without this, XFinder cannot create its
-- tables and you'll see "permission denied for schema public".
GRANT ALL ON SCHEMA public TO xfinder;
EOF
```

### Step 4 – Configure XFinder

```bash
cd XFinder
python3.13 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your DB credentials and optional API keys
```

### Step 5 – Verify Installation

```bash
python install.py
```

You should see all green checkmarks. If anything is red, follow the printed instructions.

### Step 6 – Launch XFinder

```bash
python main.py
```

The CLI initializes the database schema on first run, then displays the main menu.

---

## 2. Running Your First Scan

### Option A – Subdomain Discovery (Quickest)

1. From the main menu, type `1` and press Enter.
2. Enter the target domain (e.g., `example.com`).
3. Accept the default thread count (20) or enter your own.
4. Accept the default timeout or override.
5. XFinder runs Subfinder and displays a summary table.

### Option B – Full Scan (Most Thorough)

1. From the main menu, type `7`.
2. Enter the target domain.
3. Configure threads (recommended: 50 for production, 10 for slow networks).
4. Configure timeout (recommended: 60 seconds).
5. XFinder runs the entire pipeline:
   - Subfinder → dnsx → httpx → Naabu → Nmap → Katana → Nuclei
6. A summary table shows each scanner's status, duration, and notes.
7. A changes table shows differences vs the previous scan (if any).
8. The output directory path is printed at the end.

### Option C – Targeted Scans

Each menu option runs a specific subset of the pipeline:

| Option | Scan Type        | Scanners Run                                  |
| ------ | ---------------- | --------------------------------------------- |
| 1      | Subdomain        | Subfinder                                     |
| 2      | DNS              | Subfinder → dnsx                              |
| 3      | Cloud            | Subfinder → dnsx → httpx (+ cloud detection)  |
| 4      | Port             | Subfinder → dnsx → httpx → Naabu              |
| 5      | Web/API          | Subfinder → dnsx → httpx → Katana             |
| 6      | Vulnerability    | Subfinder → dnsx → httpx → Nuclei             |
| 7      | Full             | All of the above + Nmap                       |

---

## 3. Understanding the Output

### Console Output

After each scan, XFinder prints:

```text
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Scan completed in 142.34s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Scanner   ┃ Status ┃ Duration ┃ Notes                              ┃
┡━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ subfinder │   OK   │  12.34s  │ 145 subdomains                     │
│ dnsx      │   OK   │   8.21s  │ 142 items                          │
│ httpx     │   OK   │  23.45s  │ 87 live hosts                      │
│ naabu     │   OK   │  31.20s  │ 312 open ports                     │
│ nmap      │   OK   │  45.67s  │ 156 services                       │
│ katana    │   OK   │  15.32s  │ 421 endpoints                      │
│ nuclei    │   OK   │   6.15s  │ 12 findings                        │
└───────────┴────────┴──────────┴────────────────────────────────────┘
```

If any scanner fails, its row turns red and the Notes column shows the error.

### Changes Table

If a previous scan exists for the same target, XFinder also prints:

```text
┏━━━━━━━━━━━━━━━━━━━━ Changes vs previous scan ━━━━━━━━━━━━━━━━━━━━┓
┃ Category        ┃  New ┃ Removed ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━┩
│ Subdomains      │   3  │    1    │
│ Open Ports      │   8  │    2    │
│ Technologies    │   2  │    0    │
│ Vulnerabilities │   4  │    1    │
│ API Endpoints   │  17  │    3    │
│ DNS changes     │   5  │    -    │
│ Cloud changes   │   1  │    -    │
└─────────────────┴──────┴─────────┘
```

### File Output

All scan data is written to `output/<target>/<timestamp>/`. Each file is described in [README.md → JSON Output Structure](../README.md#json-output-structure).

---

## 4. Scheduling Recurring Scans

After every successful scan, XFinder asks:

```text
Run this scan automatically every 60 minutes?
[Y] Yes   [N] No
```

If you answer **Yes**, the scan is registered with the background scheduler. The job will fire at the configured interval until you exit the CLI or explicitly unschedule it.

### Notes

- The scheduler runs in a background thread. The CLI remains interactive while scans run.
- Minimum interval is **5 minutes**. Shorter intervals are rejected to prevent accidental DoS.
- If a scheduled scan is still running when the next one is due, APScheduler coalesces them (no overlap).
- Scheduled jobs do **not** persist across CLI restarts. To make them persist, modify `scheduler/scheduler.py` to use a SQLAlchemyJobStore (future enhancement).

### Managing Scheduled Jobs

Currently, scheduled jobs are listed by inspecting the scheduler object:

```python
from scheduler.scheduler import get_scheduler
sched = get_scheduler()
for job in sched.list_jobs():
    print(f"{job.target} / {job.scan_type} every {job.interval_minutes}m")
```

To unschedule:

```python
sched.unschedule("example.com", "full")
```

A future CLI menu option will expose this interactively.

---

## 5. Reviewing Scan History

Choose menu option **8 – View Previous Scans** to:

1. List all targets you've ever scanned.
2. Pick a target by ID.
3. See a chronological table of every scan: ID, type, status, started-at, duration.

This data comes from the `scans` table. History is append-only — scans are never overwritten.

### Comparing Two Scans

To see detailed differences between two scans:

```bash
# From the output directory:
diff output/example.com/2026-07-01_10-00-00/subdomains.json \
     output/example.com/2026-07-01_11-00-00/subdomains.json
```

Or read the auto-generated `changes.json` in the latest scan's directory.

---

## 6. Working with JSON Reports

Each scan produces 10 JSON files. All files share a common envelope:

```json
{
  "scan_id": 42,
  "target": "example.com",
  "exported_at": "2026-07-01T10:00:00Z",
  "data": [ ... ]
}
```

### Programmatic Access

```python
import json
from pathlib import Path

scan_dir = Path("output/example.com/2026-07-01_10-00-00")

# Load vulnerabilities
with (scan_dir / "vulnerabilities.json").open() as f:
    vulns = json.load(f)["data"]

for v in vulns:
    if v["severity"] in ("critical", "high"):
        print(f"[!] {v['name']} on {v['matched_url']}")
```

### Integrating with SIEM/SOAR

The JSON schema is stable and documented. Common integration patterns:

- **Splunk**: use a `monitor` input on `output/*/vulnerabilities.json`.
- **ELK**: ship via Filebeat with JSON codec.
- **PagerDuty**: trigger on `severity == "critical"` in `vulnerabilities.json`.

---

## 7. Configuring Performance

Tune scan performance via `.env`:

| Setting            | Effect                                                      |
| ------------------ | ----------------------------------------------------------- |
| `DEFAULT_THREADS`  | Concurrency for all tools. Higher = faster, but more load.  |
| `SCAN_RATE`        | Packets/requests per second. Lower for fragile networks.    |
| `*_TIMEOUT`        | Per-tool timeout in seconds. Increase for slow links.       |
| `NUCLEI_SEVERITY`  | Filter Nuclei templates. Use `high,critical` for fast triage. |

### Recommended Profiles

**Production (datacenter, fast link):**
```ini
DEFAULT_THREADS=50
SCAN_RATE=2000
NUCLEI_SEVERITY=low,medium,high,critical
```

**Slow/Remote (mobile, residential):**
```ini
DEFAULT_THREADS=5
SCAN_RATE=100
NUCLEI_SEVERITY=high,critical
```

**Quick Triage (verify known exposures only):**
```ini
DEFAULT_THREADS=20
SCAN_RATE=1000
NUCLEI_SEVERITY=critical
```

---

## 8. Using Enrichment APIs

XFinder integrates with Shodan and VirusTotal for additional context.

### Shodan

1. Get an API key at <https://account.shodan.io/register>.
2. Set `SHODAN_API_KEY` in `.env`.
3. Shodan enrichment runs as part of the ASN enrichment step on each resolved IP.

Shodan returns: ASN, organization, ISP, country, city, open ports, services, banners, tags, known vulnerabilities.

### VirusTotal

1. Get an API key at <https://www.virustotal.com/gui/my-apikey>.
2. Set `VIRUSTOTAL_API_KEY` in `.env`.
3. VirusTotal enrichment runs on the apex domain.

VirusTotal returns: reputation score, last analysis stats (harmless/malicious/suspicious/undetected), categories, favicon hash, registrar.

### Free Enrichment (No API Keys Required)

These modules work without any API keys:

- **Cloud Detection** — uses CNAME chains and HTTP headers
- **ASN** — uses Team Cymru's free `origin.asn.cymru.com` DNS service
- **SSL** — connects to port 443 and reads the certificate
- **WHOIS/RDAP** — uses the free `rdap.org` service

---

## 9. Operating in Production

### Log Management

Logs rotate automatically at 5 MB per file, keeping 5 backups. Location: `logs/xfinder.log`.

```bash
# Watch live logs
tail -f logs/xfinder.log

# Filter for errors
grep "| ERROR" logs/xfinder.log
```

### Disk Space

Each scan produces ~1-5 MB of JSON per target, depending on the asset count. Plan for ~50 GB per year per 100 targets if scanning hourly.

To prune old scans (manual):

```bash
# Delete scans older than 90 days (filesystem)
find output/ -type d -name "202[0-9]-*" -mtime +90 -exec rm -rf {} \;
```

To prune old scans (database) — not currently exposed; write a one-off SQL query:

```sql
DELETE FROM scans WHERE started_at < NOW() - INTERVAL '90 days';
```

### Database Maintenance

Recommended PostgreSQL maintenance:

```sql
-- Weekly vacuum
VACUUM ANALYZE;

-- Monthly reindex
REINDEX DATABASE xfinder;
```

### Security Considerations

- **API Keys** — store `.env` outside version control (already in `.gitignore`).
- **Database** — use a dedicated PostgreSQL role with `SELECT, INSERT, UPDATE` only; no `DROP`.
- **Nmap** — `-O` (OS detection) requires root. Either run as root (not recommended) or accept that OS detection will be skipped.
- **Nuclei** — templates can be intrusive. Review the template list with `nuclei -tl` before scanning production assets.

### Backup

Back up both the database and the JSON output:

```bash
# Database
pg_dump -Fc xfinder > xfinder_$(date +%Y%m%d).dump

# Output directory
tar czf xfinder_output_$(date +%Y%m%d).tar.gz output/
```

---

## Next Steps

- Read the [Troubleshooting Guide](TROUBLESHOOTING.md) for common issues.
- Review the [Architecture Document](ARCHITECTURE.md) for deep internals.
- Browse [sample reports](../samples/) to see real-world output formats.
