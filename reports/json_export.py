"""JSON export + change detection.

This module produces the per-scan JSON files defined in the spec:

    output/<target>/<timestamp>/
        subdomains.json
        dns.json
        http.json
        cloud.json
        ports.json
        services.json
        technologies.json
        api.json
        vulnerabilities.json
        changes.json
        full_scan.json

It also implements change detection between two scan summaries, producing
a structured diff covering subdomains, ports, technologies, DNS, cloud,
and vulnerabilities.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.helpers import ensure_dir, write_json
from utils.logger import get_logger

logger = get_logger(__name__)


class JsonExporter:
    """Writes per-scan JSON files and computes change diffs."""

    # ------------------------------------------------------------- writers

    @staticmethod
    def write_scan_output(scan_id: int, target: str, output_dir: Path,
                          summary: Dict[str, Any]) -> Dict[str, Path]:
        """Write the full set of per-scan JSON files.

        Returns a dict mapping filename -> resolved path.
        """
        output_dir = ensure_dir(output_dir)
        written: Dict[str, Path] = {}

        files = {
            "subdomains.json":      summary.get("subdomains", []),
            "dns.json":             summary.get("dns", []),
            "http.json":            summary.get("http", []),
            "cloud.json":           summary.get("cloud", []),
            "ports.json":           summary.get("ports", []),
            "services.json":        summary.get("services", []),
            "technologies.json":    summary.get("technologies", []),
            "api.json":             summary.get("api_endpoints", []),
            "vulnerabilities.json": summary.get("vulnerabilities", []),
        }
        for fname, payload in files.items():
            p = write_json(output_dir / fname, {
                "scan_id": scan_id,
                "target": target,
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "data": payload,
            })
            written[fname] = p

        return written

    @staticmethod
    def write_changes(output_dir: Path, changes: Dict[str, Any]) -> Path:
        """Write ``changes.json`` for a scan."""
        return write_json(Path(output_dir) / "changes.json", changes)

    # ------------------------------------------------------------- change detection

    @staticmethod
    def compute_changes(
        previous: Dict[str, Any],
        current: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compute a structured diff between two scan summaries.

        Both inputs are produced by ``Repository.get_scan_summary`` and
        therefore share the same schema.

        Returns a dict with keys:

        * ``new_subdomains``, ``removed_subdomains``
        * ``new_ports``, ``closed_ports``
        * ``new_technologies``, ``removed_technologies``
        * ``dns_changes``
        * ``cloud_changes``
        * ``new_vulnerabilities``, ``resolved_vulnerabilities``
        * ``new_api_endpoints``, ``removed_api_endpoints``
        * ``summary`` – counts per category
        """
        changes: Dict[str, Any] = {}

        # ---- subdomains
        prev_subs: Set[str] = set(previous.get("subdomains", []))
        curr_subs: Set[str] = set(current.get("subdomains", []))
        changes["new_subdomains"] = sorted(curr_subs - prev_subs)
        changes["removed_subdomains"] = sorted(prev_subs - curr_subs)

        # ---- ports (identified by (ip_id, port, proto))
        def port_key(p: Dict[str, Any]) -> Tuple[Any, Any, str]:
            return (p.get("ip_id"), p.get("port"), p.get("proto", "tcp"))

        prev_ports = {port_key(p) for p in previous.get("ports", [])}
        curr_ports = {port_key(p) for p in current.get("ports", [])}
        changes["new_ports"] = [list(k) for k in sorted(curr_ports - prev_ports)]
        changes["closed_ports"] = [list(k) for k in sorted(prev_ports - curr_ports)]

        # ---- technologies (identified by (http_info_id, category, name))
        def tech_key(t: Dict[str, Any]) -> Tuple[Any, Optional[str], str]:
            return (t.get("http_info_id"), t.get("category"), t.get("name", ""))

        prev_tech = {tech_key(t) for t in previous.get("technologies", [])}
        curr_tech = {tech_key(t) for t in current.get("technologies", [])}
        changes["new_technologies"] = [list(k) for k in sorted(curr_tech - prev_tech)]
        changes["removed_technologies"] = [list(k) for k in sorted(prev_tech - curr_tech)]

        # ---- DNS changes (per subdomain)
        prev_dns = _index_dns(previous.get("dns", []))
        curr_dns = _index_dns(current.get("dns", []))
        changes["dns_changes"] = _diff_dns(prev_dns, curr_dns)

        # ---- cloud changes (per subdomain)
        prev_cloud = _index_cloud(previous.get("cloud", []))
        curr_cloud = _index_cloud(current.get("cloud", []))
        changes["cloud_changes"] = _diff_cloud(prev_cloud, curr_cloud)

        # ---- vulnerabilities (identified by (template_id, matched_url))
        def vuln_key(v: Dict[str, Any]) -> Tuple[str, Optional[str]]:
            return (v.get("template_id", ""), v.get("url"))

        prev_vulns = {vuln_key(v) for v in previous.get("vulnerabilities", [])}
        curr_vulns = {vuln_key(v) for v in current.get("vulnerabilities", [])}
        changes["new_vulnerabilities"] = [list(k) for k in sorted(curr_vulns - prev_vulns)]
        changes["resolved_vulnerabilities"] = [list(k) for k in sorted(prev_vulns - curr_vulns)]

        # ---- API endpoints
        prev_api: Set[str] = set(previous.get("api_endpoints", []))
        curr_api: Set[str] = set(current.get("api_endpoints", []))
        changes["new_api_endpoints"] = sorted(curr_api - prev_api)
        changes["removed_api_endpoints"] = sorted(prev_api - curr_api)

        # ---- summary
        changes["summary"] = {
            "new_subdomains":         len(changes["new_subdomains"]),
            "removed_subdomains":     len(changes["removed_subdomains"]),
            "new_ports":              len(changes["new_ports"]),
            "closed_ports":           len(changes["closed_ports"]),
            "new_technologies":       len(changes["new_technologies"]),
            "removed_technologies":   len(changes["removed_technologies"]),
            "dns_changed_subdomains": len(changes["dns_changes"]),
            "cloud_changed_subdomains": len(changes["cloud_changes"]),
            "new_vulnerabilities":    len(changes["new_vulnerabilities"]),
            "resolved_vulnerabilities": len(changes["resolved_vulnerabilities"]),
            "new_api_endpoints":      len(changes["new_api_endpoints"]),
            "removed_api_endpoints":  len(changes["removed_api_endpoints"]),
        }
        return changes


# --------------------------------------------------------------------------- helpers

def _index_dns(rows: List[Dict[str, Any]]) -> Dict[int, Dict[str, List[str]]]:
    """Group DNS records by subdomain_id, then by record_type -> [values]."""
    out: Dict[int, Dict[str, List[str]]] = {}
    for r in rows:
        sd = r.get("subdomain_id")
        if sd is None:
            continue
        rtype = (r.get("type") or "").upper()
        val = r.get("value", "")
        out.setdefault(sd, {}).setdefault(rtype, []).append(val)
    return out


def _diff_dns(prev: Dict[int, Dict[str, List[str]]],
              curr: Dict[int, Dict[str, List[str]]]) -> List[Dict[str, Any]]:
    """Return per-subdomain DNS diff."""
    out: List[Dict[str, Any]] = []
    all_sds = set(prev) | set(curr)
    for sd in sorted(all_sds):
        p = prev.get(sd, {})
        c = curr.get(sd, {})
        added: List[Dict[str, str]] = []
        removed: List[Dict[str, str]] = []
        for rtype in set(p) | set(c):
            pset = set(p.get(rtype, []))
            cset = set(c.get(rtype, []))
            for v in sorted(cset - pset):
                added.append({"type": rtype, "value": v})
            for v in sorted(pset - cset):
                removed.append({"type": rtype, "value": v})
        if added or removed:
            out.append({
                "subdomain_id": sd,
                "added": added,
                "removed": removed,
            })
    return out


def _index_cloud(rows: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    out: Dict[int, Dict[str, Any]] = {}
    for r in rows:
        sd = r.get("subdomain_id")
        if sd is None:
            continue
        out[sd] = {
            "provider": r.get("provider"),
            "cdn": r.get("cdn"),
            "waf": r.get("waf"),
        }
    return out


def _diff_cloud(prev: Dict[int, Dict[str, Any]],
                curr: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for sd in sorted(set(prev) | set(curr)):
        p = prev.get(sd, {})
        c = curr.get(sd, {})
        if p != c:
            out.append({
                "subdomain_id": sd,
                "previous": p,
                "current": c,
            })
    return out
