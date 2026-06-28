# XFinder – Troubleshooting Guide

This guide covers the most common issues users encounter with XFinder and how to resolve them. Issues are grouped by category.

## Table of Contents

1. [Installation Issues](#1-installation-issues)
2. [Database Issues](#2-database-issues)
3. [Scanner Issues](#3-scanner-issues)
4. [API / Enrichment Issues](#4-api--enrichment-issues)
5. [Performance Issues](#5-performance-issues)
6. [CLI Issues](#6-cli-issues)
7. [Scheduler Issues](#7-scheduler-issues)
8. [JSON Output Issues](#8-json-output-issues)
9. [Test Failures](#9-test-failures)

---

## 1. Installation Issues

### `python install.py` reports a tool as MISSING even though it's installed

**Cause:** The tool is installed but not on your `$PATH` in the shell session running `install.py`.

**Fix:**
```bash
# Find the tool's location
which subfinder
# Or for Go-installed tools:
ls $HOME/go/bin/

# Add to PATH (and add to ~/.bashrc / ~/.zshrc to make permanent)
export PATH=$PATH:$HOME/go/bin

# Verify
subfinder -version
```

Then re-run `python install.py`.

### `go install` fails with "go: command not found"

**Cause:** Go is not installed.

**Fix:**
```bash
# Debian/Ubuntu
sudo apt-get install -y golang-go

# Or download the latest from https://go.dev/dl/
wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### `nuclei -update-templates` fails with rate limit

**Cause:** ProjectDiscovery rate-limits template downloads.

**Fix:** Wait 5-10 minutes and retry. Alternatively, install templates manually from <https://github.com/projectdiscovery/nuclei-templates>.

### pip install fails with "error: externally-managed-environment"

**Cause:** Newer Python distributions (PEP 668) prevent pip from modifying the system Python.

**Fix:** Use a virtual environment:
```bash
python3.13 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Database Issues

### "Database: UNREACHABLE" when launching `python main.py`

**Cause:** PostgreSQL isn't running, or credentials are wrong.

**Diagnosis:**
```bash
# Is PostgreSQL running?
sudo systemctl status postgresql

# Can you connect with psql?
psql -h localhost -U xfinder -d xfinder
```

**Fixes:**
- Start PostgreSQL: `sudo systemctl start postgresql`
- Reset password: `sudo -u postgres psql -c "ALTER USER xfinder WITH PASSWORD 'newpass';"`
- Update `.env` with the correct credentials.
- Verify `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` in `.env`.

### "FATAL: database 'xfinder' does not exist"

**Cause:** The database hasn't been created yet.

**Fix:**
```bash
sudo -u postgres psql <<EOF
CREATE USER xfinder WITH PASSWORD 'yourpass';
CREATE DATABASE xfinder OWNER xfinder;
GRANT ALL PRIVILEGES ON DATABASE xfinder TO xfinder;
EOF
```

### "permission denied for table scans"

**Cause:** The `xfinder` user lacks privileges on the schema.

**Fix:**
```sql
sudo -u postgres psql -d xfinder <<EOF
GRANT ALL ON SCHEMA public TO xfinder;
GRANT ALL ON ALL TABLES IN SCHEMA public TO xfinder;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO xfinder;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO xfinder;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO xfinder;
EOF
```

### "permission denied for schema public" during `init_db()` (PostgreSQL 15+)

**Cause:** PostgreSQL 15 (released 2022) tightened the default privileges on the `public` schema. Non-superusers no longer get `CREATE` permission by default, so XFinder cannot create its tables even though you ran `GRANT ALL ON DATABASE xfinder TO xfinder`.

**Diagnosis:**
```bash
psql -h localhost -U xfinder -d xfinder -c "\dn+"
# Look at the privileges for the 'public' schema — you'll see
# xfinder is missing 'C' (CREATE) and 'U' (USAGE) or both.
```

**Fix — grant CREATE on the public schema:**
```bash
sudo -u postgres psql -d xfinder -c "GRANT ALL ON SCHEMA public TO xfinder;"
```

**Fix — or make xfinder the database owner (more thorough):**
```bash
sudo -u postgres psql -c "ALTER DATABASE xfinder OWNER TO xfinder;"
sudo -u postgres psql -d xfinder -c "GRANT ALL ON SCHEMA public TO xfinder;"
```

**Verify the fix worked:**
```bash
psql -h localhost -U xfinder -d xfinder -c "CREATE TABLE _test_perm(id int); DROP TABLE _test_perm;"
# If this succeeds without error, XFinder's init_db() will also succeed.
```

Then re-run XFinder — `init_db()` will create all 12 tables automatically.

### Tables aren't being created

**Cause:** `init_db()` failed silently during startup. Check `logs/xfinder.log` for the actual error.

**Fix:** Force schema creation:
```bash
python -c "from config.database import init_db; init_db()"
```

If that fails, the error message will tell you exactly what's wrong.

### Schema drift after upgrading XFinder

**Cause:** XFinder's `create_all()` is idempotent for new tables but doesn't migrate existing ones.

**Fix:** Drop and recreate (destructive — back up first!):
```sql
DROP DATABASE xfinder;
CREATE DATABASE xfinder OWNER xfinder;
```
Then re-run `python main.py`.

For non-destructive migrations, use Alembic (planned for a future release).

---

## 3. Scanner Issues

### Subfinder returns 0 subdomains

**Possible causes:**
1. No internet access to passive sources.
2. Subfinder API keys (GitHub, Shodan, etc.) not configured.
3. The target genuinely has no public subdomains.

**Diagnosis:**
```bash
subfinder -d example.com -v
```

**Fixes:**
- Configure Subfinder API keys: <https://github.com/projectdiscovery/subfinder#usage>
- Run with `-all` flag (already enabled in XFinder).

### dnsx returns "no answers"

**Cause:** All subdomains failed to resolve, OR the DNS server is blocking you.

**Fix:**
- Try a different resolver: add `-r 1.1.1.1,8.8.8.8` to the dnsx command in `scanners/dnsx.py`.
- Check if your network blocks outbound DNS: `dig @1.1.1.1 example.com`.

### httpx reports "connection refused" for everything

**Cause:** Outbound HTTP/HTTPS is blocked by your firewall.

**Fix:**
- Test from the same host: `curl -v https://example.com`.
- If using a corporate proxy, set `HTTP_PROXY` and `HTTPS_PROXY` environment variables before running XFinder.

### Naabu reports "no open ports" but you know ports are open

**Cause:** Naabu's default syn scan requires root. Without root, it falls back to connect scan, which is slower and may time out.

**Fix:**
- Run XFinder with `sudo` (not recommended for production).
- Or increase `NAABU_TIMEOUT` in `.env` to 60+ seconds.

### Nmap crashes with "OS detection requires root"

**Cause:** Nmap's `-O` flag requires CAP_NET_RAW.

**Fix:** Either:
1. Run with sudo (security risk).
2. Remove `-O` from the Nmap command in `scanners/nmap.py` (OS detection will be skipped, but service detection still works).
3. Use Linux capabilities: `sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)`.

### Nuclei returns 0 findings

**Cause:** Nuclei templates haven't been downloaded.

**Fix:**
```bash
nuclei -update-templates
```

Verify templates exist:
```bash
ls ~/nuclei-templates/
```

### Nuclei crashes with "no templates found for tags"

**Cause:** Technology-aware tag selection is too restrictive.

**Fix:** Edit `scanners/nuclei.py` and comment out the tech-tag selection logic, or expand the `tag_map` dictionary.

### Katana crashes with "sandbox" error

**Cause:** Katana's headless browser sandbox requires additional system libraries.

**Fix:** Either install the dependencies (complex), or use the `-no-sandbox` flag (already added in XFinder's Katana wrapper). If still failing, set `KATANA_TIMEOUT=300` in `.env`.

---

## 4. API / Enrichment Issues

### Shodan returns "Invalid API key"

**Cause:** The API key in `.env` is wrong, expired, or has a typo.

**Fix:**
- Verify at <https://account.shodan.io/>.
- Update `SHODAN_API_KEY` in `.env`.
- Restart XFinder (the CLI caches the key on startup).

### Shodan returns "rate limit exceeded"

**Cause:** Free Shodan API keys are limited to 1 request/second.

**Fix:**
- Wait 60 seconds and retry.
- Upgrade to a paid Shodan plan.
- Or skip Shodan enrichment by leaving `SHODAN_API_KEY` empty.

### VirusTotal returns "404 Not Found"

**Cause:** The domain has never been scanned by VirusTotal.

**Fix:** This is informational, not an error. XFinder records this as an "error" in the enrichment dict but the scan continues normally.

### ASN enrichment returns no data

**Cause:** Team Cymru's DNS service may be slow or the IP may not have ASN info (rare for public IPs).

**Fix:**
- Increase the timeout in `enrichment/asn.py` (line: `lifetime=10`).
- Or use a paid service like IPinfo for more reliable data.

### SSL enrichment fails with "SSL error"

**Cause:** The host doesn't serve HTTPS on port 443, or its certificate is invalid.

**Fix:** This is expected behavior. XFinder records the error and continues. To verify manually:
```bash
openssl s_client -connect example.com:443 -servername example.com
```

---

## 5. Performance Issues

### Scans are very slow

**Causes & Fixes:**

1. **Thread count too low.** Increase `DEFAULT_THREADS` in `.env` (try 50).
2. **Scan rate too low.** Increase `SCAN_RATE` to 2000.
3. **Timeouts too generous.** Reduce `*_TIMEOUT` values.
4. **Nmap is scanning too many ports.** The default port list in `scanners/naabu.py` (`DEFAULT_PORTS`) is already trimmed to ~50 common ports. You can reduce further.
5. **Network is slow.** Use a cloud VM closer to the target.

### High CPU usage

**Cause:** Too many concurrent scanners.

**Fix:** Reduce `DEFAULT_THREADS` to 10 or lower.

### Out of memory

**Cause:** Very large targets (10,000+ subdomains) can exhaust memory during enrichment.

**Fix:**
- Increase available RAM.
- Or process in batches by editing `scanners/engine.py` to chunk the subdomain list.

### Database writes are slow

**Cause:** Many small INSERTs instead of batched writes.

**Fix:** XFinder already uses batched writes via the Repository layer. If still slow:
- Increase PostgreSQL `shared_buffers` (in `postgresql.conf`).
- Run `VACUUM ANALYZE` to optimize query plans.

---

## 6. CLI Issues

### CLI hangs after launching

**Cause:** The DB initialization step is blocking because PostgreSQL is unreachable.

**Fix:** Press `Ctrl+C` to interrupt, then fix the DB connection (see Section 2).

### Colors don't display correctly

**Cause:** Your terminal doesn't support ANSI escape codes.

**Fix:** Set `TERM=xterm-256color` in your environment, or use a modern terminal emulator (iTerm2, Windows Terminal, Alacritty, Kitty).

### CLI crashes with "AttributeError: 'NoneType' object has no attribute 'id'"

**Cause:** A scan was interrupted mid-way and left inconsistent state.

**Fix:** Check `logs/xfinder.log` for the stack trace. Most likely the engine tried to persist a scanner result but the parent Subdomain row was never created.

If this happens repeatedly, file a bug with the log file attached.

---

## 7. Scheduler Issues

### Scheduled scans don't fire

**Causes & Fixes:**

1. **Scheduler not started.** It starts automatically when you answer "Y" to the post-scan prompt. If you manually close the CLI before then, scheduled jobs are lost.
2. **CLI exited.** Scheduled jobs live in-process; they die when the CLI exits. To run scheduled scans unattended, see "Headless Mode" below.
3. **Job is past its `next_run_time` due to misfire.** APScheduler's misfire grace time is 300s. If the CLI was unresponsive for >5 minutes, the job is dropped.

### Headless Mode (Future Feature)

XFinder currently requires the interactive CLI to be running for the scheduler to fire. To run scheduled scans unattended today, use cron:

```bash
# crontab -e
0 * * * * cd /path/to/XFinder && /path/to/python -c "
from scanners.engine import ScanEngine
ScanEngine().run(target='example.com', scan_type='full')
"
```

### Multiple schedulers running

**Cause:** You launched the CLI multiple times.

**Fix:** Kill all but one process:
```bash
ps aux | grep main.py
kill <PID>
```

The scheduler is in-memory only, so killing the process is safe.

---

## 8. JSON Output Issues

### `changes.json` is empty / has `"first_scan": true`

**Cause:** This is the first scan ever for this target. There's no previous scan to compare against.

**Fix:** Run a second scan — the next `changes.json` will contain a real diff.

### `full_scan.json` is missing a scanner

**Cause:** That scanner failed. Look in `logs/xfinder.log` for the error.

### JSON files contain `null` values where you expected data

**Cause:** The scanner returned partial data. XFinder records what it could and leaves the rest as `null` rather than fabricating values.

**Fix:** Run the failing scanner standalone to diagnose:
```bash
httpx -u https://example.com -status-code -title -server -tech-detect
```

### Unicode characters in JSON appear as `\uXXXX`

**Cause:** XFinder writes JSON with `ensure_ascii=False`, so this shouldn't happen. If you see escape sequences, you may be opening the file with the wrong encoding.

**Fix:** Open with `encoding='utf-8'`:
```bash
cat output/example.com/.../subdomains.json  # should display correctly
python -c "import json; print(json.load(open('...', encoding='utf-8')))"
```

---

## 9. Test Failures

### `ModuleNotFoundError: No module named 'sqlalchemy'` in tests

**Cause:** Test dependencies aren't installed.

**Fix:**
```bash
pip install -r requirements.txt
pip install pytest pytest-cov pytest-mock responses
```

### Tests fail with `sqlite3.IntegrityError: NOT NULL constraint failed`

**Cause:** You're running tests against an older version of the models that used `BigInteger` for primary keys (SQLite doesn't autoincrement those).

**Fix:** Update to the latest version of `database/models.py` which uses `BigInteger().with_variant(Integer, "sqlite")`.

### Scheduler tests fail intermittently

**Cause:** APScheduler uses background threads, which can race with test teardown.

**Fix:** Re-run the tests; transient failures resolve on retry. If they persist, increase the scheduler's `misfire_grace_time` in the test fixture.

### Coverage is below 100%

**Cause:** XFinder doesn't claim 100% coverage. Current coverage focuses on:
- Validators (100%)
- Helpers (100%)
- Settings (100%)
- Cloud detection (100%)
- Change detection (100%)
- Database repository (>80%)
- Engine integration (smoke test)

**To improve coverage**, add tests for:
- Each scanner's `_parse_*` method (using sample tool output as fixtures).
- Enrichment modules (mock `requests.get` and `dns.resolver`).

---

## Still Stuck?

1. Check the full log: `logs/xfinder.log`.
2. Run the failing tool standalone to isolate the issue.
3. Search existing GitHub issues: <https://github.com/your-org/xfinder/issues>.
4. Open a new issue with:
   - XFinder version (`git rev-parse HEAD`)
   - Python version (`python --version`)
   - OS (`uname -a`)
   - The relevant excerpt from `logs/xfinder.log`
   - The command you ran
   - What you expected vs. what happened
