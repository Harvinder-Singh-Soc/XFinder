"""
utils.py — Shared utilities for XFinder-CTEM
"""
import os, re, json, shutil, subprocess
from typing import List, Tuple, Any

def run_cmd(cmd: List[str], timeout: int = 120, stdin_text: str = None) -> Tuple[bool, str, str]:
    """Run a subprocess command, return (success, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=stdin_text, check=False)
        return r.returncode == 0, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "TIMEOUT"
    except FileNotFoundError:
        return False, "", f"NOT_FOUND:{cmd[0]}"
    except Exception as e:
        return False, "", str(e)


def safe_jsonl(text: str) -> List[dict]:
    """Parse JSONL text into list of dicts."""
    out = []
    if not text:
        return out
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def sanitize(text: Any, max_len: int = 10000) -> Any:
    """Strip NUL and control characters from text."""
    if text is None:
        return None
    if isinstance(text, (int, float, bool)):
        return text
    if not isinstance(text, str):
        text = str(text)
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return cleaned[:max_len] if len(cleaned) > max_len else cleaned


def find_bin(name: str) -> str:
    """Find binary — check GOPATH FIRST (PD tools), then PATH.
    For httpx, verifies it's PD httpx (not Python httpx)."""
    # Check GOPATH locations first
    gopath = os.environ.get("GOPATH", "")
    candidates = []
    if gopath:
        candidates.append(f"{gopath}/bin/{name}")
    candidates.extend([
        os.path.expanduser("~/gopath/bin/" + name),
        os.path.expanduser("~/go/bin/" + name),
        "/home/z/gopath/bin/" + name,
    ])
    for c in candidates:
        if os.path.exists(c):
            return c
    # Then check PATH
    p = shutil.which(name)
    if p:
        if name == "httpx":
            # Verify it's PD httpx, not Python httpx
            try:
                r = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=5)
                out = (r.stdout or "") + (r.stderr or "")
                if "projectdiscovery" in out.lower() or "current version" in out.lower():
                    return p
            except:
                pass
        else:
            return p
    # Then common system locations
    for c in [f"/usr/local/bin/{name}", f"/usr/bin/{name}", f"/home/z/nmap-install/bin/{name}"]:
        if os.path.exists(c):
            return c
    return None
