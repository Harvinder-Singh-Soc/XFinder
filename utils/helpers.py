"""General-purpose helpers shared across the XFinder codebase.

Includes:

* ``run_subprocess``   – safe subprocess wrapper with timeout + retries.
* ``chunked``          – split an iterable into fixed-size batches.
* ``safe_json_loads``  – tolerant JSON parsing.
* ``timestamp_str``    – filesystem-safe timestamp formatter.
* ``parse_csv_line``   – tolerant CSV-like line parser used by scanner outputs.
* ``dedupe_preserve_order`` – ordered de-duplication of a sequence.
* ``guess_scheme``     – prepend http(s):// to a bare host when needed.
* ``sanitize_text``    – strip NUL and control chars that break PostgreSQL.
* ``sanitize_dict``    – recursively sanitize all strings in a dict/list.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional, Sequence, Tuple


# --------------------------------------------------------------------------- subprocess

@dataclass(slots=True)
class CommandResult:
    """Result of a subprocess invocation."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_subprocess(
    cmd: Sequence[str] | str,
    *,
    timeout: int = 60,
    retries: int = 1,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    input_text: Optional[str] = None,
) -> CommandResult:
    """Run an external command with timeout and retry semantics.

    Parameters
    ----------
    cmd:
        Either a list of args (preferred) or a single shell string. When a
        string is passed, ``shlex.split`` is used to tokenize it safely.
    timeout:
        Hard timeout in seconds per attempt.
    retries:
        Number of attempts on transient failure (timeout or non-zero exit).
        Default 1 means a single attempt.
    cwd, env, input_text:
        Optional ``subprocess`` overrides.

    Returns
    -------
    CommandResult
        Captured stdout/stderr, return code, and timing info.
    """
    if isinstance(cmd, str):
        args = shlex.split(cmd)
    else:
        args = list(cmd)

    attempts = max(1, retries)
    last_result: CommandResult = CommandResult(
        returncode=-1, stdout="", stderr="", timed_out=False
    )

    for attempt in range(1, attempts + 1):
        start = datetime.now()
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=env,
                input=input_text,
                check=False,
            )
            duration = (datetime.now() - start).total_seconds()
            last_result = CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                timed_out=False,
                duration_seconds=duration,
            )
            if last_result.ok:
                return last_result
        except subprocess.TimeoutExpired as exc:
            duration = (datetime.now() - start).total_seconds()
            last_result = CommandResult(
                returncode=-1,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                timed_out=True,
                duration_seconds=duration,
            )
        except FileNotFoundError as exc:
            # Tool not installed – do not retry, return immediately.
            return CommandResult(
                returncode=127, stdout="", stderr=str(exc), timed_out=False
            )
        except Exception as exc:  # pragma: no cover - defensive
            last_result = CommandResult(
                returncode=-1, stdout="", stderr=str(exc), timed_out=False
            )

    return last_result


# --------------------------------------------------------------------------- iteration helpers

def chunked(iterable: Iterable[Any], size: int) -> Iterator[List[Any]]:
    """Yield successive lists of length *size* from *iterable*.

    >>> list(chunked(range(7), 3))
    [[0, 1, 2], [3, 4, 5], [6]]
    """
    if size < 1:
        raise ValueError("chunk size must be >= 1")
    batch: List[Any] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def dedupe_preserve_order(items: Iterable[Any]) -> List[Any]:
    """Remove duplicates while preserving first-seen order.

    >>> dedupe_preserve_order([3, 1, 3, 2, 1])
    [3, 1, 2]
    """
    seen: set = set()
    out: List[Any] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


# --------------------------------------------------------------------------- json helpers

def safe_json_loads(text: str) -> Optional[Any]:
    """Parse *text* as JSON, returning ``None`` on failure."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def safe_jsonl_loads(text: str) -> List[dict]:
    """Parse newline-delimited JSON (JSONL) into a list of dicts.

    Lines that fail to parse are silently skipped – scanner output can be
    noisy and we do not want a single bad line to abort a scan.
    """
    out: List[dict] = []
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = safe_json_loads(line)
        if isinstance(obj, dict):
            out.append(obj)
    return out


# --------------------------------------------------------------------------- misc

def timestamp_str(dt: Optional[datetime] = None) -> str:
    """Filesystem-safe timestamp string (e.g. ``2026-07-01_10-00``)."""
    dt = dt or datetime.now()
    return dt.strftime("%Y-%m-%d_%H-%M-%S")


def parse_csv_line(line: str, delimiter: str = ",") -> List[str]:
    """Parse a CSV-like line into trimmed fields, skipping empties."""
    if not line:
        return []
    return [f.strip() for f in line.split(delimiter) if f.strip()]


def guess_scheme(host: str, prefer_https: bool = True) -> str:
    """Build a URL with a guessed scheme for a bare host."""
    if host.startswith("http://") or host.startswith("https://"):
        return host
    return f"{'https' if prefer_https else 'http'}://{host}"


def ensure_dir(path: str | Path) -> Path:
    """Create directory *path* (and parents) if it does not exist."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def write_json(path: str | Path, data: Any) -> Path:
    """Write *data* as pretty JSON to *path*, returning the resolved path."""
    p = Path(path)
    ensure_dir(p.parent)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=False)
    return p


def first_or_none(seq: Iterable[Any], default: Any = None) -> Any:
    """Return the first item of *seq* or *default* if empty."""
    for item in seq:
        return item
    return default


# --------------------------------------------------------------------------- sanitization

# Pattern matching NUL bytes and other control chars that PostgreSQL TEXT
# columns cannot store (NUL is the main offender, but we strip all C0
# control chars except tab/newline/carriage-return for safety).
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: Any, max_length: int = 10000) -> Any:
    """Strip NUL and control characters from a string.

    PostgreSQL TEXT columns reject strings containing NUL (0x00) bytes with
    ``ValueError: A string literal cannot contain NUL (0x00) characters``.
    Scanner tools (especially katana) sometimes emit these in HTTP response
    bodies, URLs, and form fields. This function strips them safely.

    Also truncates overly long strings to avoid blowing up DB column limits.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        # Convert non-strings (int, float, bool) to string for safety
        if isinstance(value, (int, float, bool)):
            return value
        value = str(value)
    # Remove NUL and other control chars
    cleaned = _CONTROL_CHAR_RE.sub("", value)
    # Truncate if too long
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def sanitize_dict(obj: Any, max_length: int = 10000) -> Any:
    """Recursively sanitize all strings in a dict, list, or tuple.

    Walks the entire structure and applies :func:`sanitize_text` to every
    string value. Returns a new structure with the same shape but with all
    strings cleaned of NUL/control characters.

    Use this on scanner output before persisting to PostgreSQL.
    """
    if obj is None:
        return None
    if isinstance(obj, str):
        return sanitize_text(obj, max_length)
    if isinstance(obj, dict):
        return {sanitize_text(k, max_length): sanitize_dict(v, max_length)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        cleaned = [sanitize_dict(item, max_length) for item in obj]
        return cleaned if isinstance(obj, list) else tuple(cleaned)
    # int, float, bool, etc. — return as-is
    return obj

