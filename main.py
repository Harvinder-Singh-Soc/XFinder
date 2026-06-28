"""XFinder entry point.

Usage::

    python main.py

Initializes the database schema (idempotent) and launches the Rich CLI.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel

from config.database import init_db, test_connection
from utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


def _is_schema_permission_error(exc: Exception) -> bool:
    """Detect the PostgreSQL 15+ 'permission denied for schema public' error."""
    msg = str(exc).lower()
    return "permission denied for schema" in msg and "public" in msg


def _is_connection_error(exc: Exception) -> bool:
    """Detect a connection-level failure (host unreachable, auth failed, etc.)."""
    msg = str(exc).lower()
    return any(s in msg for s in (
        "could not connect",
        "connection refused",
        "authentication failed",
        "password authentication failed",
        "no such file or directory",
        "server closed the connection unexpectedly",
    ))


def main() -> int:
    """Initialize DB and launch CLI."""
    console.print("[bold cyan]XFinder starting...[/bold cyan]")
    logger.info("XFinder entry point reached")

    # Try to initialize the database schema. We do not abort on failure –
    # the CLI can still be used to explore the menu, and the user can fix
    # DB credentials from the Configuration option.
    try:
        init_db()
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc, exc_info=True)

        if _is_schema_permission_error(exc):
            # PostgreSQL 15+ no longer grants CREATE on public by default.
            console.print(Panel.fit(
                "[bold red]Database: schema permission error[/bold red]\n\n"
                "PostgreSQL 15+ does not grant CREATE on the 'public' schema to\n"
                "non-superusers by default. Run this command as the postgres\n"
                "superuser, then restart XFinder:\n\n"
                "[cyan]sudo -u postgres psql -d xfinder "
                "-c \"GRANT ALL ON SCHEMA public TO xfinder;\"[/cyan]\n\n"
                f"[dim]Original error:[/dim] {exc}",
                title="[bold red]DB Setup Required[/bold red]",
                border_style="red",
            ))
        elif _is_connection_error(exc):
            console.print(Panel.fit(
                "[bold red]Database: connection failed[/bold red]\n\n"
                "Could not reach PostgreSQL. Check:\n"
                "  1. PostgreSQL is running: [cyan]sudo systemctl status postgresql[/cyan]\n"
                "  2. Credentials in [cyan].env[/cyan] match your PostgreSQL role.\n"
                "  3. The database [cyan]xfinder[/cyan] exists: "
                "[cyan]sudo -u postgres psql -c '\\l'[/cyan]\n\n"
                f"[dim]Original error:[/dim] {exc}",
                title="[bold red]DB Connection Failed[/bold red]",
                border_style="red",
            ))
        else:
            console.print(f"[yellow]Warning:[/yellow] Database initialization failed: {exc}")
            console.print("[yellow]You can still browse the menu, but scans will fail until "
                          "PostgreSQL is reachable. Use option 9 (Configuration) to test "
                          "the connection.[/yellow]")
    else:
        if test_connection():
            console.print("[green]Database: connected.[/green]")
        else:
            console.print("[yellow]Warning:[/yellow] Database schema created but connection "
                          "test failed. Check credentials in .env.")

    # Lazy import to avoid importing Rich CLI before logging is configured.
    from cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
