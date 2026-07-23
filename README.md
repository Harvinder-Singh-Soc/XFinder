# XFinder-CTEM Integrated Scanner

A complete External Attack Surface Management (EASM) tool that scans targets and automatically syncs results to CTEM Supabase database.

## Project Structure

```
XFinder-CTEM/
├── run.py                  # Main file — scan + sync (run this)
├── utils.py                # Shared utilities (helpers, binary finder)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── scanners/               # Scanner modules (one per tool)
│   ├── __init__.py
│   ├── nuclei.py           # Vulnerability scanning
│   ├── subfinder.py        # Subdomain enumeration
│   ├── dnsx.py             # DNS resolution
│   ├── httpx.py            # Live HTTP detection
│   ├── naabu.py            # Port discovery
│   ├── nmap.py             # Service detection
│   └── katana.py           # Web crawling
└── output/                 # Scan results (auto-created)
```

## Installation

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Install Go (for ProjectDiscovery tools)

```bash
# Ubuntu/Debian/Kali
sudo apt-get install -y golang-go

# Set GOPATH
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Add to ~/.bashrc or ~/.zshrc for persistence
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
```

### Step 3: Install Scanning Tools

```bash
# Install all ProjectDiscovery tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Nmap
sudo apt-get install -y nmap

# Install Nuclei templates (required for vulnerability scanning)
nuclei -update-templates
```

### Step 4: Verify Installation

```bash
python run.py --target example.com --no-sync
```

You should see all 7 tools marked with ✓ and scan results.

### Step 5: (Optional) Configure API Keys

For Shodan and VirusTotal enrichment, set environment variables:

```bash
# Shodan API Key (get from https://account.shodan.io/)
export SHODAN_API_KEY="your_shodan_api_key"

# VirusTotal API Key (get from https://www.virustotal.com/gui/my-apikey)
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
```

### Step 6: Configure CTEM Supabase

The Supabase credentials are pre-configured in `run.py`:

```python
SUPABASE_URL = "https://eqlolqdgviakidyinwrt.supabase.co"
SUPABASE_KEY = "sb_publishable_bvXFa9QnkBIC7ZYNbY_bUw_VN5shl4z"
```

To override, set environment variables:

```bash
export SUPABASE_URL="your_supabase_url"
export SUPABASE_KEY="your_supabase_key"
```

## Usage

### Interactive Mode

```bash
python run.py
```

Then enter a target domain:
```
  Target domain (or 'exit'): hackerone.com
  Sync to Supabase? [Y/n]: Y
```

### Direct Mode

```bash
# Scan + auto-sync to CTEM Supabase
python run.py --target hackerone.com

# Scan without Supabase sync (local JSON only)
python run.py --target hackerone.com --no-sync
```

## Scan Workflow

```
Target (e.g., hackerone.com)
  │
  ├─ 1. Nuclei    → Vulnerability scanning (runs FIRST on target directly)
  ├─ 2. Subfinder → Subdomain enumeration
  ├─ 3. dnsx      → DNS resolution (A/AAAA/CNAME/MX/TXT/NS/SOA)
  ├─ 4. httpx     → Live HTTP detection + fingerprinting
  ├─ 5. Naabu     → Port discovery (only on live hosts)
  ├─ 6. Nmap      → Service detection (only on found ports)
  └─ 7. Katana    → Web crawling + endpoint discovery
       │
       ├─ Save JSON to output/<target>/<timestamp>/
       └─ Auto-sync to CTEM Supabase:
            → assets table
            → dns_records table
            → open_ports table
            → vulnerabilities table
            → scans table
```

## Output

Each scan creates a timestamped folder:

```
output/hackerone.com/2026-07-23_13-30-00/
├── nuclei.json          # Vulnerability findings
├── subfinder.json       # Discovered subdomains
├── dnsx.json            # DNS records
├── httpx.json           # Live HTTP hosts
├── naabu.json           # Open ports
├── nmap.json            # Service detection
└── katana.json          # Crawled endpoints
```

## CTEM Supabase Sync

After scanning, results are automatically pushed to the CTEM Supabase database:

| XFinder Output | CTEM Table | Description |
|---|---|---|
| subfinder.json | assets | Subdomains become assets |
| dnsx.json | dns_records | DNS records with upsert |
| naabu.json + nmap.json | open_ports | Ports with service info |
| nuclei.json | vulnerabilities | Vulnerability findings |
| (metadata) | scans | Scan run record |

## Troubleshooting

### "PD httpx not found"
The Python `httpx` package conflicts with ProjectDiscovery's `httpx`. Fix:
```bash
# Ensure GOPATH/bin is in PATH BEFORE Python's bin
export PATH=$GOPATH/bin:$PATH
```

### "Nuclei returns 0 findings"
Ensure templates are installed:
```bash
nuclei -update-templates
# Verify:
ls ~/nuclei-templates/
```

### "Supabase sync failed"
Check your Supabase URL and key. Test connection:
```python
from supabase import create_client
db = create_client("URL", "KEY")
print(db.table("assets").select("*").limit(1).execute())
```

### "Tool not found"
Verify all tools are installed:
```bash
which subfinder dnsx httpx naabu katana nuclei nmap
```

## Tested Targets

This tool has been tested on:
- hackerone.com ✅
- google.com ✅
- facebook.com ✅
- instagram.com ✅
- tesla.com ✅
- eccouncil.org ✅
