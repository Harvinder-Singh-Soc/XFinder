"""XFinder command-line interface (Rich-based SOC-style menu)."""

from __future__ import annotations

import logging
import sys
import time
from typing import Any, Dict, List, Optional

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text

from config.database import test_connection
from config.settings import settings
from database.repository import Repository
from scanners.engine import ScanEngine
from scanners.registry import SCAN_LABELS, list_scan_types
from scheduler.scheduler import get_scheduler
from utils.logger import get_logger
from utils.validators import is_valid_domain, normalize_domain

logger = get_logger(__name__)
console = Console()

# Menu items in display order (1-indexed for the user).
MENU_ITEMS: List[tuple] = [
    ("1",  "subdomain",     "Subdomain Discovery"),
    ("2",  "dns",           "DNS Enumeration"),
    ("3",  "cloud",         "Cloud Discovery"),
    ("4",  "port",          "Port Discovery"),
    ("5",  "webapi",        "Web/API Discovery"),
    ("6",  "vulnerability", "Vulnerability Scan"),
    ("7",  "full",          "Full Scan"),
    ("8",  "__history__",   "View Previous Scans"),
    ("9",  "__config__",    "Configuration"),
    ("10", "__exit__",      "Exit"),
]


# --------------------------------------------------------------------------- banner

def print_banner() -> None:
    """Render the XFinder banner."""
    banner = Text()
    banner.append("=" * 40 + "\n", style="bold cyan")
    banner.append("\n           XFinder\n\n", style="bold white")
    banner.append(" External Attack Surface Management\n\n", style="cyan")
    banner.append("=" * 40 + "\n", style="bold cyan")

    menu_text = Text()
    for num, _, label in MENU_ITEMS:
        menu_text.append(f"  {num}. {label}\n", style="white")

    console.print(Panel(Align.center(banner), border_style="cyan"))
    console.print(Panel(menu_text, title="[bold]Main Menu[/bold]",
                        title_align="left", border_style="cyan"))


# --------------------------------------------------------------------------- prompts

def prompt_target() -> Optional[str]:
    """Prompt the user for a target domain. Returns None on cancel."""
    raw = Prompt.ask("[bold cyan]Enter target domain[/bold cyan] (or 'back')")
    if raw.strip().lower() in {"back", "b", "exit", "quit"}:
        return None
    domain = normalize_domain(raw)
    if not is_valid_domain(domain):
        console.print(f"[red]Invalid domain:[/red] {raw!r}")
        return None
    return domain


def prompt_scan_type() -> Optional[str]:
    """Prompt the user to choose a scan type from the menu."""
    choice = Prompt.ask(
        "[bold cyan]Select an option[/bold cyan]",
        choices=[m[0] for m in MENU_ITEMS],
        show_choices=False,
    )
    for num, key, _ in MENU_ITEMS:
        if num == choice:
            return key
    return None


# --------------------------------------------------------------------------- scan flow

def run_scan_flow(scan_type: str) -> None:
    """Full flow for a scan: prompt target, run, ask to schedule."""
    target = prompt_target()
    if not target:
        return

    threads = IntPrompt.ask(
        "[cyan]Threads[/cyan]",
        default=settings.default_threads,
    )
    timeout = IntPrompt.ask(
        "[cyan]Timeout (seconds)[/cyan]",
        default=settings.nmap_timeout,
    )

    console.print()
    console.rule(f"[bold yellow]Starting {SCAN_LABELS.get(scan_type, scan_type)} on {target}[/bold yellow]")

    engine = ScanEngine()
    # Live progress: print start message; engine logs each scanner through logging.
    start = time.time()
    outcome = engine.run(target=target, scan_type=scan_type,
                         threads=threads, timeout=timeout)
    duration = time.time() - start

    _print_scan_outcome(outcome)

    # Ask whether to schedule
    if outcome.success:
        _ask_schedule(target, scan_type)


def _print_scan_outcome(outcome: Any) -> None:
    """Render a Rich summary table of a completed scan."""
    if outcome.success:
        title = f"[bold green]Scan completed in {outcome.duration_seconds:.2f}s[/bold green]"
    else:
        title = f"[bold red]Scan failed after {outcome.duration_seconds:.2f}s[/bold red]"

    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("Scanner", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Notes", overflow="fold")

    for name, res in outcome.scanner_results.items():
        status = "[green]OK[/green]" if res.success else "[red]FAIL[/red]"
        notes = res.error or _summarize_data(res.data) or "-"
        table.add_row(name, status, f"{res.duration_seconds:.2f}s", notes)

    console.print(table)

    if outcome.changes and not outcome.changes.get("first_scan"):
        _print_changes(outcome.changes)

    if outcome.output_dir:
        console.print(f"\n[cyan]Output directory:[/cyan] {outcome.output_dir}")


def _summarize_data(data: Dict[str, Any]) -> str:
    """One-line human summary of a scanner's data payload."""
    if not data:
        return ""
    if "subdomains" in data:
        return f"{len(data['subdomains'])} subdomains"
    if "resolved_count" in data:
        return f"{data['resolved_count']} resolved / {data.get('record_count', 0)} records"
    if "hosts" in data:
        return f"{len(data['hosts'])} live hosts"
    if "open_ports" in data:
        return f"{len(data['open_ports'])} open ports"
    if "services" in data:
        return f"{len(data['services'])} services"
    if "endpoints" in data:
        return f"{len(data['endpoints'])} endpoints"
    if "vulnerabilities" in data:
        sev = data.get("by_severity", {})
        sev_str = " ".join(f"{k}:{v}" for k, v in sorted(sev.items()))
        return f"{len(data['vulnerabilities'])} findings ({sev_str})"
    if "count" in data:
        return f"{data['count']} items"
    return ""


def _print_changes(changes: Dict[str, Any]) -> None:
    summary = changes.get("summary", {})
    if not summary:
        return
    table = Table(title="[bold yellow]Changes vs previous scan[/bold yellow]",
                  show_header=True, header_style="bold yellow")
    table.add_column("Category", style="white")
    table.add_column("New", justify="right", style="green")
    table.add_column("Removed", justify="right", style="red")

    table.add_row("Subdomains",     str(summary.get("new_subdomains", 0)),
                  str(summary.get("removed_subdomains", 0)))
    table.add_row("Open Ports",     str(summary.get("new_ports", 0)),
                  str(summary.get("closed_ports", 0)))
    table.add_row("Technologies",   str(summary.get("new_technologies", 0)),
                  str(summary.get("removed_technologies", 0)))
    table.add_row("Vulnerabilities",str(summary.get("new_vulnerabilities", 0)),
                  str(summary.get("resolved_vulnerabilities", 0)))
    table.add_row("API Endpoints",  str(summary.get("new_api_endpoints", 0)),
                  str(summary.get("removed_api_endpoints", 0)))
    table.add_row("DNS changes",    str(summary.get("dns_changed_subdomains", 0)), "-")
    table.add_row("Cloud changes",  str(summary.get("cloud_changed_subdomains", 0)), "-")
    console.print(table)


def _ask_schedule(target: str, scan_type: str) -> None:
    """Prompt the user to schedule the same scan hourly."""
    console.print()
    answer = Confirm.ask(
        f"[bold yellow]Run this scan automatically every {settings.scan_interval_minutes} minutes?[/bold yellow]",
        default=False,
    )
    if not answer:
        return
    sched = get_scheduler()
    sched.start()
    record = sched.schedule(target=target, scan_type=scan_type,
                            interval_minutes=settings.scan_interval_minutes)
    console.print(f"[green]Scheduled.[/green] Job ID: {record.job_id}, "
                  f"next run: {record.next_run}")


# --------------------------------------------------------------------------- history / config

def view_history() -> None:
    """Display previous scans for any of the user's targets."""
    targets = Repository.list_targets()
    if not targets:
        console.print("[yellow]No targets scanned yet.[/yellow]")
        return

    target_names = {str(t.id): t.domain for t in targets}
    console.print("\n[bold cyan]Choose a target:[/bold cyan]")
    for tid, name in target_names.items():
        console.print(f"  {tid}. {name}")
    choice = Prompt.ask("Target ID", default="1")
    target = next((t for t in targets if str(t.id) == choice), None)
    if target is None:
        console.print("[red]Invalid target ID.[/red]")
        return

    scans = Repository.list_scans_for_target(target.id, limit=50)
    if not scans:
        console.print(f"[yellow]No scans recorded for {target.domain}.[/yellow]")
        return

    table = Table(title=f"[bold]Scan History for {target.domain}[/bold]",
                  show_header=True, header_style="bold cyan")
    table.add_column("Scan ID", style="white")
    table.add_column("Type", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Started", style="white")
    table.add_column("Duration", justify="right")
    for s in scans:
        status_color = "green" if s.status == "completed" else (
            "red" if s.status == "failed" else "yellow"
        )
        table.add_row(
            str(s.id),
            s.scan_type,
            f"[{status_color}]{s.status}[/{status_color}]",
            s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
            f"{s.duration_seconds:.1f}s" if s.duration_seconds else "-",
        )
    console.print(table)


def view_config() -> None:
    """Display current configuration and DB connectivity."""
    table = Table(title="[bold]Configuration[/bold]", show_header=True,
                  header_style="bold cyan")
    table.add_column("Setting", style="white")
    table.add_column("Value", overflow="fold")

    rows = [
        ("DB Host",        settings.db_host),
        ("DB Port",        str(settings.db_port)),
        ("DB Name",        settings.db_name),
        ("Default Threads",str(settings.default_threads)),
        ("Nmap Timeout",   f"{settings.nmap_timeout}s"),
        ("Scan Interval",  f"{settings.scan_interval_minutes} min"),
        ("Output Dir",     str(settings.output_path)),
        ("Log Level",      settings.log_level),
        ("Shodan Key",     "[green]SET[/green]" if settings.shodan_api_key else "[red]NOT SET[/red]"),
        ("VT Key",         "[green]SET[/green]" if settings.virustotal_api_key else "[red]NOT SET[/red]"),
    ]
    for k, v in rows:
        table.add_row(k, v)
    console.print(table)

    # DB connectivity
    console.print()
    console.print("[cyan]Testing database connection...[/cyan]")
    if test_connection():
        console.print("[green]Database: OK[/green]")
    else:
        console.print("[red]Database: UNREACHABLE[/red]")
        console.print(f"  Checked DSN: {settings.database_url.split('@')[-1] if '@' in settings.database_url else '***'}")


# --------------------------------------------------------------------------- main loop

def main() -> int:
    """Entry point for the CLI.

    Returns an exit code (0 on clean exit, non-zero on error).
    """
    logger.info("XFinder CLI started")
    try:
        while True:
            console.print()
            print_banner()
            choice = Prompt.ask(
                "[bold cyan]Select an option (1-10)[/bold cyan]",
                choices=[m[0] for m in MENU_ITEMS],
                show_choices=False,
            )

            action = next((m[1] for m in MENU_ITEMS if m[0] == choice), None)
            if action is None:
                console.print("[red]Invalid choice.[/red]")
                continue

            if action == "__exit__":
                console.print("[bold cyan]Shutting down...[/bold cyan]")
                # Stop scheduler if running
                sched = get_scheduler()
                if sched.is_started():
                    sched.shutdown(wait=False)
                console.print("[green]Goodbye![/green]")
                return 0
            elif action == "__history__":
                view_history()
            elif action == "__config__":
                view_config()
            elif action in list_scan_types():
                run_scan_flow(action)
            else:
                console.print(f"[red]Unknown action: {action}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return 130
    except Exception as exc:
        logger.exception("CLI crashed: %s", exc)
        console.print(f"[red]Fatal error:[/red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
