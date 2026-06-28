"""XFinder installer / dependency verifier.

Verifies that all required system tools and Python packages are installed
and provides actionable installation instructions for anything missing.

Run::

    python install.py

The script NEVER crashes on missing dependencies – it prints clear
instructions and exits with a non-zero code so it can be used in CI.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


# --------------------------------------------------------------------------- dependency spec

@dataclass(slots=True)
class Dependency:
    name: str
    kind: str            # "system" | "python"
    required: bool = True
    install_cmd: str = ""
    install_url: str = ""
    min_version: str = ""
    check_args: Tuple[str, ...] = ("--version",)


SYSTEM_TOOLS: List[Dependency] = [
    Dependency(
        name="python", kind="system", required=True,
        min_version="3.13",
        install_url="https://www.python.org/downloads/",
        check_args=("--version",),
    ),
    Dependency(
        name="postgresql", kind="system", required=True,
        install_cmd="sudo apt-get install -y postgresql postgresql-contrib",
        install_url="https://www.postgresql.org/download/",
        # psql uses --version (works on all PG versions 9.x-17.x)
        check_args=("--version",),
    ),
    Dependency(
        name="subfinder", kind="system", required=True,
        install_cmd="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        install_url="https://github.com/projectdiscovery/subfinder#installation",
    ),
    Dependency(
        name="dnsx", kind="system", required=True,
        install_cmd="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        install_url="https://github.com/projectdiscovery/dnsx#installation",
    ),
    Dependency(
        name="httpx", kind="system", required=True,
        install_cmd="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        install_url="https://github.com/projectdiscovery/httpx#installation",
    ),
    Dependency(
        name="naabu", kind="system", required=True,
        install_cmd="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        install_url="https://github.com/projectdiscovery/naabu#installation",
    ),
    Dependency(
        name="nmap", kind="system", required=True,
        install_cmd="sudo apt-get install -y nmap",
        install_url="https://nmap.org/download.html",
    ),
    Dependency(
        name="katana", kind="system", required=True,
        install_cmd="go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        install_url="https://github.com/projectdiscovery/katana#installation",
    ),
    Dependency(
        name="nuclei", kind="system", required=True,
        install_cmd="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        install_url="https://github.com/projectdiscovery/nuclei#installation",
    ),
]

PYTHON_DEPS_FILE = "requirements.txt"


# --------------------------------------------------------------------------- check helpers

def check_system_tool(dep: Dependency) -> Tuple[bool, str]:
    """Return (installed, version_string)."""
    path = shutil.which(dep.name)
    binary_name = dep.name  # the actual binary we'll invoke for version check
    if path is None:
        # Some tools install under different binary names; check aliases.
        aliases = {
            "postgresql": ["psql", "postgres", "pg_ctl"],
            "httpx":      ["httpx"],  # projectdiscovery's httpx (not Python's)
        }
        for alias in aliases.get(dep.name, []):
            path = shutil.which(alias)
            if path:
                binary_name = alias
                break
    if path is None:
        return False, ""

    try:
        result = subprocess.run(
            [binary_name, *dep.check_args],
            capture_output=True, text=True, timeout=10, check=False,
        )
        version = (result.stdout or result.stderr).strip().splitlines()[0] if (result.stdout or result.stderr) else ""
        return True, version
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, ""


def check_python_deps() -> Tuple[List[str], List[str]]:
    """Return (installed, missing) Python packages from requirements.txt."""
    try:
        with open(PYTHON_DEPS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return [], []

    # Strip comments and version specifiers to get plain package names.
    wanted: List[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        # Strip version specifiers
        for sep in [">=", "<=", "==", ">", "<", "!=", "~="]:
            if sep in line:
                line = line.split(sep, 1)[0].strip()
                break
        # Some packages use dashes -> underscores for import
        wanted.append(line)

    installed: List[str] = []
    missing: List[str] = []
    try:
        from importlib.metadata import distribution, PackageNotFoundError
    except ImportError:  # pragma: no cover
        return wanted, []

    for pkg in wanted:
        import_name = pkg.replace("-", "_")
        try:
            distribution(pkg)
            installed.append(pkg)
        except Exception:
            try:
                __import__(import_name)
                installed.append(pkg)
            except Exception:
                missing.append(pkg)
    return installed, missing


# --------------------------------------------------------------------------- main

def run_checks() -> int:
    """Run all dependency checks and print a Rich report.

    Returns 0 on success, 1 if any required dependency is missing.
    """
    console.print(Panel.fit(
        "[bold cyan]XFinder – Dependency Installer & Verifier[/bold cyan]",
        border_style="cyan",
    ))

    # ---- system tools
    sys_table = Table(title="[bold]System Tools[/bold]", show_header=True,
                      header_style="bold cyan")
    sys_table.add_column("Tool", style="white")
    sys_table.add_column("Status", justify="center")
    sys_table.add_column("Version", overflow="fold")

    sys_missing: List[Dependency] = []
    for dep in SYSTEM_TOOLS:
        ok, ver = check_system_tool(dep)
        status = "[green]OK[/green]" if ok else "[red]MISSING[/red]"
        sys_table.add_row(dep.name, status, ver)
        if not ok:
            sys_missing.append(dep)

    console.print(sys_table)

    # ---- python deps
    py_installed, py_missing = check_python_deps()
    py_table = Table(title="[bold]Python Packages[/bold]", show_header=True,
                     header_style="bold cyan")
    py_table.add_column("Status", justify="center")
    py_table.add_column("Count", justify="right")
    py_table.add_column("Details", overflow="fold")
    py_table.add_row(
        "[green]Installed[/green]",
        str(len(py_installed)),
        ", ".join(py_installed[:8]) + ("..." if len(py_installed) > 8 else ""),
    )
    py_table.add_row(
        "[red]Missing[/red]" if py_missing else "[green]Missing[/green]",
        str(len(py_missing)),
        ", ".join(py_missing) if py_missing else "none",
    )
    console.print(py_table)

    # ---- instructions
    if sys_missing or py_missing:
        console.print()
        console.print(Panel.fit(
            "[bold yellow]Installation Instructions[/bold yellow]",
            border_style="yellow",
        ))
        if sys_missing:
            console.print("\n[bold]Missing system tools:[/bold]")
            for dep in sys_missing:
                console.print(f"\n[white]• {dep.name}[/white]")
                if dep.install_cmd:
                    console.print(f"  [cyan]Install:[/cyan] {dep.install_cmd}")
                if dep.install_url:
                    console.print(f"  [cyan]Docs:[/cyan]   {dep.install_url}")
        if py_missing:
            console.print("\n[bold]Missing Python packages:[/bold]")
            console.print(f"  [cyan]Install:[/cyan] pip install -r {PYTHON_DEPS_FILE}")
            if py_missing:
                console.print(f"  [cyan]Or:[/cyan]     pip install {' '.join(py_missing)}")
        console.print()
        return 1

    console.print()
    console.print(Panel.fit(
        "[bold green]All dependencies are installed![/bold green]\n"
        "Next steps:\n"
        "  1. Copy .env.example to .env and configure DB credentials.\n"
        "  2. Create the PostgreSQL database and user.\n"
        "  3. Run: python main.py",
        border_style="green",
    ))
    return 0


def main() -> int:
    return run_checks()


if __name__ == "__main__":
    sys.exit(main())
