# XFinder – Architecture Diagram

The architecture is documented in two forms:

1. **Mermaid diagram** (renders on GitHub) — below.
2. **ASCII art diagram** — see [README.md → Architecture](../README.md#architecture).

## Mermaid Source

```mermaid
flowchart TD
    %% Entry points
    CLI[CLI<br/>cli.py<br/>Rich TUI]
    SCHED[Scheduler<br/>scheduler/scheduler.py<br/>APScheduler]
    CRON[Cron / External<br/>triggers ScanEngine.run]

    %% Engine
    ENGINE[Scan Engine<br/>scanners/engine.py<br/>orchestrates the chain<br/>persists results<br/>computes changes]

    %% Scanner plugins
    SUBF[SubfinderScanner<br/>passive subdomain enum]
    DNSX[DnsxScanner<br/>A/AAAA/CNAME/MX/TXT/NS/SOA]
    HTTPX[HttpxScanner<br/>live HTTP + fingerprint]
    NAABU[NaabuScanner<br/>fast TCP ports]
    NMAP[NmapScanner<br/>service/version/OS]
    KATANA[KatanaScanner<br/>web crawl + API discovery]
    NUCLEI[NucleiScanner<br/>tech-aware template scan]

    %% Enrichment
    CLOUD[enrichment/cloud.py<br/>CNAME + headers + server]
    ASN[enrichment/asn.py<br/>Team Cymru DNS]
    SSL[enrichment/ssl.py<br/>cert metadata]
    WHOIS[enrichment/whois.py<br/>RDAP + WHOIS]
    SHODAN[enrichment/shodan.py<br/>Shodan API]
    VT[enrichment/virustotal.py<br/>VT v3 API]

    %% Storage
    REPO[Repository<br/>database/repository.py<br/>batched writes + analytics]
    DB[(PostgreSQL<br/>12 normalized tables)]
    JSON[JSON Reports<br/>reports/json_export.py<br/>per-scan timestamped]
    LOGS[Rotating Logs<br/>utils/logger.py]

    %% Flow
    CLI --> ENGINE
    SCHED --> ENGINE
    CRON --> ENGINE

    ENGINE --> SUBF
    SUBF --> DNSX
    DNSX --> HTTPX
    HTTPX --> NAABU
    HTTPX --> KATANA
    HTTPX --> NUCLEI
    NAABU --> NMAP

    HTTPX -.enriches.-> CLOUD
    HTTPX -.enriches.-> SSL
    NAABU -.enriches.-> ASN
    ENGINE -.apex.-> WHOIS
    ENGINE -.apex.-> SHODAN
    ENGINE -.apex.-> VT

    ENGINE --> REPO
    REPO --> DB

    ENGINE --> JSON
    ENGINE --> LOGS

    %% Styling
    classDef entry fill:#4a90e2,stroke:#2c5f9e,color:#fff
    classDef engine fill:#e2a04a,stroke:#9e6b2c,color:#fff
    classDef scanner fill:#50c878,stroke:#2c8f56,color:#fff
    classDef enrich fill:#9b59b6,stroke:#6c3a77,color:#fff
    classDef storage fill:#e74c3c,stroke:#a02a1c,color:#fff

    class CLI,SCHED,CRON entry
    class ENGINE engine
    class SUBF,DNSX,HTTPX,NAABU,NMAP,KATANA,NUCLEI scanner
    class CLOUD,ASN,SSL,WHOIS,SHODAN,VT enrich
    class REPO,DB,JSON,LOGS storage
```

## Scan-Workflow Sequence Diagram

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as CLI
    participant E as ScanEngine
    participant DB as PostgreSQL
    participant S1 as Subfinder
    participant S2 as dnsx
    participant S3 as httpx
    participant S4 as Naabu
    participant S5 as Nmap
    participant S6 as Katana
    participant S7 as Nuclei
    participant FS as JSON files

    U->>CLI: Choose scan type + target
    CLI->>E: run(target, scan_type)
    E->>DB: INSERT scan (status=running)
    E->>S1: execute()
    S1-->>E: subdomains[]
    E->>DB: bulk_insert_subdomains
    E->>FS: write subdomains.json

    E->>S2: execute()
    S2-->>E: dns records
    E->>DB: insert DNS records
    E->>FS: write dns.json

    E->>S3: execute()
    S3-->>E: live hosts + tech
    E->>DB: upsert http_info, technologies, ips
    E->>FS: write http.json

    E->>S4: execute()
    S4-->>E: open ports
    E->>DB: add_port
    E->>FS: write ports.json

    E->>S5: execute()
    S5-->>E: services
    E->>DB: add_service
    E->>FS: write services.json

    E->>S6: execute()
    S6-->>E: endpoints
    E->>DB: bulk_insert_api_endpoints
    E->>FS: write api.json

    E->>S7: execute()
    S7-->>E: findings
    E->>DB: bulk_insert_vulnerabilities
    E->>FS: write vulnerabilities.json

    E->>DB: get previous scan summary
    E->>E: compute changes
    E->>FS: write changes.json
    E->>FS: write full_scan.json
    E->>DB: UPDATE scan (status=completed, duration)
    E-->>CLI: ScanOutcome
    CLI-->>U: Render table + changes table
    CLI->>U: "Schedule hourly? [Y/N]"
```

## Database ER Diagram

```mermaid
erDiagram
    targets ||--o{ scans : "has"
    scans ||--o{ subdomains : "contains"
    scans ||--o{ dns_records : "contains"
    scans ||--o{ http_information : "contains"
    scans ||--o{ cloud_assets : "contains"
    scans ||--o{ ip_addresses : "contains"
    scans ||--o{ api_endpoints : "contains"
    scans ||--o{ vulnerabilities : "contains"

    subdomains ||--o{ dns_records : "has"
    subdomains ||--|| http_information : "has"
    subdomains ||--o| cloud_assets : "has"
    subdomains ||--o{ ip_addresses : "resolves to"

    http_information ||--o{ technologies : "detected"

    ip_addresses ||--o{ ports : "has"
    ports ||--o{ services : "runs"

    targets {
        bigint id PK
        string domain UK
        datetime created_at
        bool is_active
    }
    scans {
        bigint id PK
        bigint target_id FK
        string scan_type
        string status
        datetime started_at
        datetime finished_at
        float duration_seconds
        string output_dir
    }
    subdomains {
        bigint id PK
        bigint scan_id FK
        bigint target_id FK
        string name
        bool is_resolved
        bool is_live_http
        string source
    }
    dns_records {
        bigint id PK
        bigint scan_id FK
        bigint subdomain_id FK
        string record_type
        text value
        int ttl
    }
    http_information {
        bigint id PK
        bigint scan_id FK
        bigint subdomain_id UK
        string url
        int status_code
        string title
        string server_header
        bigint content_length
        int response_time_ms
        string scheme
        string webserver
    }
    vulnerabilities {
        bigint id PK
        bigint scan_id FK
        string template_id
        string name
        string severity
        text description
        string matched_url
        text evidence
        float cvss_score
        datetime discovered_at
    }
```

## Plugin Architecture

```mermaid
classDiagram
    class BaseScanner {
        <<abstract>>
        +str name
        +str description
        +list required_tools
        +execute() ScanResult
        +run() ScanResult*
        +check_tools() list
        +is_available() bool
    }

    class ScanContext {
        +str target
        +int scan_id
        +int target_id
        +str output_dir
        +int threads
        +int timeout
        +int rate
        +dict cache
        +list subdomains
        +list live_hosts
        +dict ports
    }

    class ScanResult {
        +str scanner
        +bool success
        +float duration_seconds
        +dict data
        +str error
        +str raw_output
    }

    class SubfinderScanner
    class DnsxScanner
    class HttpxScanner
    class NaabuScanner
    class NmapScanner
    class KatanaScanner
    class NucleiScanner

    BaseScanner <|-- SubfinderScanner
    BaseScanner <|-- DnsxScanner
    BaseScanner <|-- HttpxScanner
    BaseScanner <|-- NaabuScanner
    BaseScanner <|-- NmapScanner
    BaseScanner <|-- KatanaScanner
    BaseScanner <|-- NucleiScanner

    BaseScanner o-- ScanContext : uses
    BaseScanner --> ScanResult : returns
```

## See Also

- [README.md → Architecture](../README.md#architecture) — narrative description.
- [User Guide](USER_GUIDE.md) — how to operate XFinder.
- [Troubleshooting](TROUBLESHOOTING.md) — common issues and fixes.
