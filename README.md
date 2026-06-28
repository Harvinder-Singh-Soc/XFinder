# XFinder

> **External Attack Surface Management (EASM)** — a lightweight, production-ready Python CLI that continuously discovers, monitors, enriches, and tracks internet-facing assets.

[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 96 passing](https://img.shields.io/badge/tests-96%20passing-success.svg)](#testing)

XFinder is **not** a script — it is a modular EASM/SOC automation framework suitable for enterprise environments and advanced cybersecurity portfolios. It orchestrates industry-standard open-source tools (Subfinder, dnsx, httpx, Naabu, Nmap, Katana, Nuclei) into an optimized scan pipeline, persists everything to PostgreSQL, generates structured JSON reports, and supports scheduled rescans with change detection.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Scan Workflow](#scan-workflow)
8. [Database Schema](#database-schema)
9. [JSON Output Structure](#json-output-structure)
10. [Change Detection](#change-detection)
11. [Scheduler](#scheduler)
12. [Extending XFinder](#extending-xfinder)
13. [Testing](#testing)
14. [Project Structure](#project-structure)
15. [User Guide](docs/USER_GUIDE.md)
16. [Troubleshooting](docs/TROUBLESHOOTING.md)
17. [Roadmap](#roadmap)
18. [License](#license)

---

## Features

### Core Capabilities
- **Subdomain Discovery** — passive enumeration via Subfinder (50+ sources)
- **DNS Resolution** — A, AAAA, CNAME, MX, TXT, NS, SOA records via dnsx
- **Live HTTP Detection** — status, title, server, redirect, content-length, response time via httpx
- **Port Discovery** — fast TCP scanning via Naabu (only against live hosts)
- **Service/Version/OS Detection** — Nmap (only against Naabu-discovered ports)
- **Web/API Crawling** — endpoint discovery via Katana
- **Vulnerability Scanning** — template-based via Nuclei (tech-aware template selection)
- **Cloud/CDN/WAF Detection** — AWS, Azure, GCP, Cloudflare, Fastly, Akamai, DigitalOcean, Vercel, Netlify, GitHub Pages
- **Asset Enrichment** — ASN, organization, country, hosting provider, reverse DNS, SSL certificate, WHOIS/RDAP, Shodan, VirusTotal

### Production-Grade Features
- **PostgreSQL persistence** with normalized tables and append-only history
- **Scheduled rescans** via APScheduler (configurable interval, minimum 5 minutes)
- **Change detection** between scans — new/removed subdomains, ports, technologies, DNS, cloud, vulnerabilities, API endpoints
- **Structured JSON reports** per scan, never overwritten
- **Professional logging** — rotating file handler + console
- **Plugin architecture** — new scanners can be added without touching the core engine
- **Rich CLI** — SOC-style menu, colored output, tables
- **Type-hinted, PEP8-compliant, fully documented** codebase
- **96 automated tests** — unit + integration coverage

### Performance Optimizations
- Never scans dead hosts (Naabu runs only after httpx confirms liveness)
- Nmap runs only against Naabu-discovered ports
- Nuclei runs only against live HTTP/HTTPS services
- Technology-aware Nuclei template selection (faster, fewer false positives)
- Configurable thread count, timeout, and scan rate per scan
- Batched database writes via repository pattern
- Intermediate results persisted in real time (survive crashes)

---

## Architecture

```text
┌──────────────────────────────────────────────────────────────────────┐
│                          XFinder CLI (Rich)                          │
│                              cli.py                                  │
└──────────────┬───────────────────────────────────────┬───────────────┘
               │                                       │
               ▼                                       ▼
┌──────────────────────────────┐         ┌─────────────────────────────┐
│      Scan Engine             │         │      Scheduler              │
│   scanners/engine.py         │         │   scheduler/scheduler.py    │
│  (orchestrates the chain)    │         │     (APScheduler)           │
└──────────────┬───────────────┘         └─────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────────┐
│              Scanner Plugins (BaseScanner subclasses)                │
│  ┌─────────────┐ ┌─────────┐ ┌────────┐ ┌────────┐ ┌──────┐ ┌──────┐ │
│  │ Subfinder   │→│  dnsx   │→│ httpx  │→│ Naabu  │→│ Nmap │→│Nuclei│ │
│  └─────────────┘ └─────────┘ └────────┘ └────────┘ └──────┘ └──────┘ │
│                                          ┌────────┐                  │
│                                          │ Katana │                  │
│                                          └────────┘                  │
└─────────────────────┬────────────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Enrichment Modules                               │
│  ┌───────┐ ┌─────┐ ┌─────┐ ┌───────┐ ┌────────┐ ┌────────────┐      │
│  │ Cloud │ │ ASN │ │ SSL │ │ WHOIS │ │ Shodan │ │ VirusTotal │      │
│  └───────┘ └─────┘ └─────┘ └───────┘ └────────┘ └────────────┘      │
└─────────────────────┬────────────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     Repository Layer                                 │
│                  database/repository.py                              │
│       (batched writes, change-detection analytics, history)          │
└─────────────────────┬────────────────────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────────────────────┐
│             PostgreSQL (SQLAlchemy ORM, 12 tables)                   │
│   targets · scans · subdomains · dns_records · http_information ·   │
│   cloud_assets · ip_addresses · ports · services · technologies ·    │
│   api_endpoints · vulnerabilities                                    │
└──────────────────────────────────────────────────────────────────────┘

                      Also writes per-scan JSON to:
                      output/<target>/<timestamp>/
                          ├── subdomains.json
                          ├── dns.json
                          ├── http.json
                          ├── cloud.json
                          ├── ports.json
                          ├── services.json
                          ├── technologies.json
                          ├── api.json
                          ├── vulnerabilities.json
                          ├── changes.json
                          └── full_scan.json
```

### Optimized Scan Workflow

```text
Target
  │
  ▼
Subfinder          (passive subdomain enumeration)
  │
  ▼
dnsx               (DNS resolution: A/AAAA/CNAME/MX/TXT/NS/SOA)
  │
  ▼
httpx              (live HTTP detection + fingerprinting)
  │
  ├──────────────┬─────────────────┬─────────────────┐
  ▼              ▼                 ▼                 ▼
Naabu        Cloud Detection   HTTP Fingerprint   Technology Detect
  │              │                 │                 │
  ▼              ▼                 ▼                 ▼
Nmap         Asset Enrichment   Server Header     Tech Stack
  │              │                 │                 │
  └──────────────┴─────────────────┴─────────────────┘
                   │
                   ▼
              Katana Crawl      (endpoints & APIs)
                   │
                   ▼
                Nuclei           (tech-aware template scan)
                   │
                   ▼
         PostgreSQL + JSON Export + Change Detection
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/xfinder.git
cd xfinder

# 2. Create & activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Copy and edit the environment file
cp .env.example .env
# Edit .env: set DB credentials and API keys

# 5. Verify all system tools are installed
python install.py

# 6. Initialize PostgreSQL database
sudo -u postgres createdb xfinder
sudo -u postgres createuser -P xfinder
sudo -u postgres psql -c "GRANT ALL ON DATABASE xfinder TO xfinder;"
# IMPORTANT (PostgreSQL 15+): grant CREATE on the public schema, otherwise
# XFinder cannot create its tables. The default public-schema privileges
# were tightened in PG 15 for security.
sudo -u postgres psql -d xfinder -c "GRANT ALL ON SCHEMA public TO xfinder;"

# 7. Launch XFinder
python main.py
```

---

## Installation

### Prerequisites

| Component          | Version  | Purpose                                            |
| ------------------ | -------- | -------------------------------------------------- |
| Python             | 3.13+    | Runtime                                            |
| PostgreSQL         | 14+      | Database                                           |
| Subfinder          | latest   | Subdomain discovery                                |
| dnsx               | latest   | DNS resolution                                     |
| httpx (PD)         | latest   | Live HTTP detection                                |
| Naabu              | latest   | Port discovery                                     |
| Nmap               | 7.92+    | Service/OS detection                               |
| Katana             | latest   | Web crawling                                       |
| Nuclei             | latest   | Vulnerability scanning                             |

### Automated Verification

```bash
python install.py
```

This script checks every dependency and prints actionable installation instructions for anything missing. It **never crashes** — it exits with code 1 if any required dependency is absent, so it can be used in CI pipelines.

### Installing the System Tools

Most projectdiscovery tools require Go:

```bash
# Install Go (https://go.dev/doc/install)
sudo apt-get install -y golang-go

# Set GOPATH (if not already)
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install all PD tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Nmap via apt
sudo apt-get install -y nmap

# Initialize Nuclei templates
nuclei -update-templates
```

---

## Configuration

All configuration is driven by environment variables loaded from `.env`:

```bash
cp .env.example .env
```

| Variable                | Default        | Description                            |
| ----------------------- | -------------- | -------------------------------------- |
| `DB_HOST`               | `localhost`    | PostgreSQL host                        |
| `DB_PORT`               | `5432`         | PostgreSQL port                        |
| `DB_NAME`               | `xfinder`      | Database name                          |
| `DB_USER`               | `xfinder`      | Database user                          |
| `DB_PASSWORD`           | *(empty)*      | Database password                      |
| `SHODAN_API_KEY`        | *(empty)*      | Shodan API key (optional)              |
| `VIRUSTOTAL_API_KEY`    | *(empty)*      | VirusTotal API key (optional)          |
| `DEFAULT_THREADS`       | `20`           | Default thread count                   |
| `HTTPX_TIMEOUT`         | `15`           | httpx timeout (seconds)                |
| `DNSX_TIMEOUT`          | `10`           | dnsx timeout (seconds)                 |
| `NAABU_TIMEOUT`         | `15`           | Naabu timeout (seconds)                |
| `NMAP_TIMEOUT`          | `60`           | Nmap timeout (seconds)                 |
| `KATANA_TIMEOUT`        | `120`          | Katana timeout (seconds)               |
| `NUCLEI_TIMEOUT`        | `180`          | Nuclei timeout (seconds)               |
| `SCAN_RATE`             | `1000`         | Packets/requests per second            |
| `SCAN_INTERVAL_MINUTES` | `60`           | Default rescan interval                |
| `OUTPUT_DIR`            | `./output`     | JSON output directory                  |
| `LOG_LEVEL`             | `INFO`         | Logging verbosity                      |
| `NUCLEI_SEVERITY`       | `low,medium,high,critical` | Nuclei severity filter      |

---

## Usage

### Interactive CLI

```bash
python main.py
```

Renders the SOC-style menu:

```text
========================================

           XFinder

 External Attack Surface Management

========================================

1. Subdomain Discovery
2. DNS Enumeration
3. Cloud Discovery
4. Port Discovery
5. Web/API Discovery
6. Vulnerability Scan
7. Full Scan
8. View Previous Scans
9. Configuration
10. Exit
```

After every scan, XFinder prompts:

```text
Run this scan automatically every 60 minutes?
[Y] Yes   [N] No
```

### Example Scans

```bash
# Launch the CLI then choose:
# 7. Full Scan
# Enter: example.com
# Threads: 50
# Timeout: 60

# Or schedule recurring scans from within the menu (option Y after a scan)
```

---

## Scan Workflow

XFinder enforces an **optimized pipeline** to avoid wasting resources:

| Step         | Tool       | Runs when                              | Output cached for next step |
| ------------ | ---------- | -------------------------------------- | --------------------------- |
| 1. Subdomains| Subfinder  | Always                                 | `ctx.subdomains`            |
| 2. DNS       | dnsx       | After step 1                           | `ctx.cache["dns_records"]`  |
| 3. Live HTTP | httpx      | After step 2 (only resolved hosts)     | `ctx.live_hosts`            |
| 4a. Ports    | Naabu      | After step 3 (only live hosts)         | `ctx.ports` (ip → ports)    |
| 4b. Cloud    | Cloud detect| After step 3                          | `ctx.cache["http_results"]` |
| 5. Services  | Nmap       | After step 4a (only on found ports)    | `ctx.cache["nmap_results"]` |
| 6. Crawl     | Katana     | After step 3                           | `ctx.cache["katana_results"]` |
| 7. Vulns     | Nuclei     | After step 3 (tech-aware templates)    | `ctx.cache["nuclei_results"]` |

The order of scanner classes in `scanners/registry.py` controls the chain. The engine never skips ahead — if step 3 finds zero live hosts, steps 4-7 are no-ops.

---

## Database Schema

12 normalized tables, all scoped by `scan_id` for append-only history:

```text
targets             (id, domain, created_at, is_active)
   │
   ├─► scans        (id, target_id, scan_type, status, started_at,
   │                finished_at, duration_seconds, error, output_dir)
   │      │
   │      ├─► subdomains      (id, scan_id, target_id, name, is_resolved,
   │      │                    is_live_http, source, created_at)
   │      │       │
   │      │       ├─► dns_records       (id, scan_id, subdomain_id,
   │      │       │                       record_type, value, ttl)
   │      │       ├─► http_information  (id, scan_id, subdomain_id, url,
   │      │       │                       status_code, title, server_header,
   │      │       │                       content_length, response_time_ms,
   │      │       │                       scheme, webserver, tech_blob)
   │      │       │       │
   │      │       │       └─► technologies  (id, scan_id, http_info_id,
   │      │       │                            category, name, version)
   │      │       ├─► cloud_assets      (id, scan_id, subdomain_id,
   │      │       │                       provider, cdn, waf, is_cloud_hosted)
   │      │       └─► ip_addresses      (id, scan_id, subdomain_id, address,
   │      │                               version, reverse_dns, asn, asn_org,
   │      │                               country, hosting_provider)
   │      │               │
   │      │               └─► ports      (id, scan_id, ip_address_id, port,
   │      │                               protocol, state)
   │      │                       │
   │      │                       └─► services  (id, scan_id, port_id,
   │      │                                        name, product, version, os)
   │      ├─► api_endpoints       (id, scan_id, source_host, method, url,
   │      │                        body, tag)
   │      └─► vulnerabilities     (id, scan_id, template_id, name, severity,
   │                               description, matched_url, matched_at,
   │                               evidence, reference_urls, tags,
   │                               cvss_score, discovered_at)
```

### Schema Initialization

On first run, `python main.py` calls `init_db()` which runs `Base.metadata.create_all(...)`. This is idempotent — safe to call repeatedly. For production migrations, use Alembic.

---

## JSON Output Structure

Every scan produces a timestamped folder:

```text
output/
└─ example.com/
   └─ 2026-07-01_10-00-00/
      ├─ subdomains.json       # All discovered subdomains
      ├─ dns.json              # DNS records per subdomain
      ├─ http.json             # HTTP fingerprint per live host
      ├─ cloud.json            # Cloud/CDN/WAF classification
      ├─ ports.json            # Open ports per IP
      ├─ services.json         # Nmap service/version/OS
      ├─ technologies.json     # Detected web technologies
      ├─ api.json              # Crawled endpoints
      ├─ vulnerabilities.json  # Nuclei findings
      ├─ changes.json          # Diff vs previous scan
      └─ full_scan.json        # Consolidated summary
```

Reports are **never overwritten**. The historical record is preserved per spec.

---

## Change Detection

After each scan, XFinder compares the current scan with the most recent previous completed scan for the same target. The diff is persisted to `changes.json` and stored in the `summary` of `full_scan.json`.

Detected change types:

- **New / Removed Subdomains**
- **New Open Ports / Closed Ports**
- **Technology Changes** (added/removed techs per HTTP service)
- **DNS Changes** (per-subdomain record additions/removals)
- **Cloud Changes** (provider/CDN/WAF transitions)
- **New / Resolved Vulnerabilities** (by template ID + matched URL)
- **New / Removed API Endpoints**

Each category is summarized in a `summary` block with counts.

---

## Scheduler

XFinder uses APScheduler's `BackgroundScheduler` for recurring scans:

```python
from scheduler.scheduler import get_scheduler

sched = get_scheduler()
sched.start()
sched.schedule(
    target="example.com",
    scan_type="full",
    interval_minutes=60,
)
```

Features:
- **No `while True` loops** — uses APScheduler's own event loop
- **Coalesce + max_instances=1** — prevents overlapping runs of the same target
- **Misfire grace time = 300s** — recovers from short downtimes
- **Replace semantics** — scheduling the same (target, scan_type) replaces the existing job
- **Minimum interval = 5 minutes** — protects against accidental DoS of your own infrastructure

---

## Extending XFinder

### Adding a New Scanner

1. Subclass `BaseScanner`:

```python
# scanners/my_tool.py
from scanners.base import BaseScanner, ScanResult
from utils.helpers import run_subprocess

class MyToolScanner(BaseScanner):
    name = "my_tool"
    description = "Does something cool"
    required_tools = ["my_tool"]

    def run(self) -> ScanResult:
        res = run_subprocess(["my_tool", self.ctx.target],
                             timeout=self.ctx.timeout)
        if not res.ok:
            return ScanResult(
                scanner=self.name, success=False,
                duration_seconds=0.0, error=res.stderr,
            )
        return ScanResult(
            scanner=self.name, success=True,
            duration_seconds=0.0,
            data={"result": res.stdout},
        )
```

2. Register it in `scanners/registry.py`:

```python
from scanners.my_tool import MyToolScanner

SCANNERS = {
    # ... existing entries ...
    "my_scan": [SubfinderScanner, MyToolScanner],
}
SCAN_LABELS["my_scan"] = "My Custom Scan"
```

3. Add persistence logic in `scanners/engine.py::_persist_result` if you want DB storage.

That's it — the CLI menu and scheduler will pick up the new scan type automatically.

### Adding a New Enrichment Module

Create a new file in `enrichment/` with an `enrich(target)` function returning a dict. See `enrichment/shodan.py` for the pattern.

---

## Testing

XFinder ships with **96 automated tests**:

```bash
# Run all tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=. --cov-report=term-missing
```

### Test Categories

| File                            | Coverage                                    |
| ------------------------------- | ------------------------------------------- |
| `test_validators.py`            | Domain/IP/URL validation                    |
| `test_helpers.py`               | Subprocess, JSON parsing, helpers           |
| `test_settings.py`              | Configuration loader                        |
| `test_cloud.py`                 | Cloud/CDN/WAF detection                     |
| `test_change_detection.py`      | Change diff logic                           |
| `test_scanners.py`              | BaseScanner + registry                      |
| `test_database.py`              | Repository layer (SQLite)                   |
| `test_scheduler.py`             | APScheduler integration                     |
| `test_engine_integration.py`    | End-to-end scan with mocked scanners        |
| `test_install.py`               | Dependency detection logic                  |

### Test Results

```text
======================= 96 passed, 33 warnings in 0.67s ========================
```

The warnings are deprecation notices from `datetime.utcnow()` (still functional in Python 3.13, scheduled for removal in a future version).

---

## Project Structure

```text
XFinder/
├── main.py                  # Entry point
├── cli.py                   # Rich CLI menu
├── config.py                # (Re-export of config.settings)
├── install.py               # Dependency verifier
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
│
├── config/
│   ├── __init__.py
│   ├── settings.py          # Pydantic settings loader
│   └── database.py          # SQLAlchemy engine + session scope
│
├── scanners/
│   ├── __init__.py
│   ├── base.py              # BaseScanner + ScanContext + ScanResult
│   ├── registry.py          # Scan-type → scanner-class mapping
│   ├── engine.py            # Orchestration engine
│   ├── subfinder.py
│   ├── dnsx.py
│   ├── httpx.py
│   ├── naabu.py
│   ├── nmap.py
│   ├── katana.py
│   └── nuclei.py
│
├── enrichment/
│   ├── __init__.py
│   ├── cloud.py             # Cloud/CDN/WAF detection
│   ├── asn.py               # ASN/org/country via Team Cymru DNS
│   ├── ssl.py               # SSL certificate metadata
│   ├── whois.py             # RDAP + WHOIS fallback
│   ├── shodan.py            # Shodan API
│   └── virustotal.py        # VirusTotal v3 API
│
├── database/
│   ├── __init__.py
│   ├── models.py            # 12 SQLAlchemy ORM models
│   └── repository.py        # Data-access layer (batched writes)
│
├── scheduler/
│   ├── __init__.py
│   └── scheduler.py         # APScheduler wrapper
│
├── reports/
│   ├── __init__.py
│   └── json_export.py       # Per-scan JSON + change detection
│
├── utils/
│   ├── __init__.py
│   ├── logger.py            # Rotating file + console logger
│   ├── helpers.py           # Subprocess, JSON, iteration helpers
│   └── validators.py        # Domain/IP/URL validation
│
├── tests/                   # 96 tests (unit + integration)
│   ├── conftest.py
│   ├── test_validators.py
│   ├── test_helpers.py
│   ├── test_settings.py
│   ├── test_cloud.py
│   ├── test_change_detection.py
│   ├── test_scanners.py
│   ├── test_database.py
│   ├── test_scheduler.py
│   ├── test_engine_integration.py
│   └── test_install.py
│
├── docs/
│   ├── USER_GUIDE.md
│   ├── TROUBLESHOOTING.md
│   ├── ARCHITECTURE.md      # This README's architecture section, expanded
│   └── architecture_diagram.md
│
├── samples/
│   ├── scan_examples/       # Sample JSON output
│   └── db_records/          # Sample DB row examples
│
└── logs/                    # Runtime logs (auto-created)
```

---

## Roadmap

- [ ] Alembic migration scripts for production schema evolution
- [ ] Web UI (FastAPI + React) for browsing scan history
- [ ] Slack/Discord/Teams alerts on new vulnerabilities
- [ ] CVSS-based risk scoring (currently disabled per spec)
- [ ] Multi-target batch scans from a CSV file
- [ ] GraphQL API for programmatic access
- [ ] Docker image (for users who want it, despite the no-Docker spec)
- [ ] Plugin marketplace (install community scanners via pip)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Disclaimer

XFinder is intended for **authorized security testing only**. Always obtain written permission before scanning infrastructure you do not own or operate. The authors are not responsible for misuse of this tool.
