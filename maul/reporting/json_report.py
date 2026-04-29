"""JSON report writer and diff engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from maul import __version__
from maul.reporting.finding import Finding, Severity


def write_json(
    findings: list[Finding],
    path: str | Path,
    *,
    domain: str = "",
    meta: dict[str, Any] | None = None,
) -> None:
    """Serialise findings to a JSON report file."""
    data = _build_report(findings, domain=domain, meta=meta)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON report produced by :func:`write_json`."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    # Deserialise findings list
    raw["findings"] = [Finding.from_dict(f) for f in raw.get("findings", [])]
    return raw


def diff_reports(
    baseline_path: str | Path,
    current_path: str | Path,
) -> dict[str, Any]:
    """Compare two JSON reports and return a structured diff.

    Returns a dict with keys:
      - new:       findings present in current but not in baseline
      - resolved:  findings present in baseline but not in current
      - escalated: findings whose severity increased
      - improved:  findings whose severity decreased
      - unchanged: findings identical in both reports
    """
    baseline = load_json(baseline_path)
    current  = load_json(current_path)

    bl_map = _findings_by_key(baseline["findings"])
    cu_map = _findings_by_key(current["findings"])

    bl_keys = set(bl_map)
    cu_keys = set(cu_map)

    new_keys      = cu_keys - bl_keys
    resolved_keys = bl_keys - cu_keys
    shared_keys   = bl_keys & cu_keys

    escalated: list[dict] = []
    improved:  list[dict] = []
    unchanged: list[Finding] = []

    for key in shared_keys:
        bl_f = bl_map[key]
        cu_f = cu_map[key]
        if cu_f.severity > bl_f.severity:
            escalated.append({"baseline": bl_f, "current": cu_f})
        elif cu_f.severity < bl_f.severity:
            improved.append({"baseline": bl_f, "current": cu_f})
        else:
            unchanged.append(cu_f)

    return {
        "baseline_meta": baseline.get("meta", {}),
        "current_meta":  current.get("meta", {}),
        "new":           [cu_map[k] for k in new_keys],
        "resolved":      [bl_map[k] for k in resolved_keys],
        "escalated":     escalated,
        "improved":      improved,
        "unchanged":     unchanged,
    }


def write_diff_json(diff: dict[str, Any], path: str | Path) -> None:
    """Serialise a diff dict to JSON."""
    serialisable = {
        "baseline_meta": diff["baseline_meta"],
        "current_meta":  diff["current_meta"],
        "summary": {
            "new":       len(diff["new"]),
            "resolved":  len(diff["resolved"]),
            "escalated": len(diff["escalated"]),
            "improved":  len(diff["improved"]),
            "unchanged": len(diff["unchanged"]),
        },
        "new":       [f.to_dict() for f in diff["new"]],
        "resolved":  [f.to_dict() for f in diff["resolved"]],
        "escalated": [
            {"baseline": e["baseline"].to_dict(), "current": e["current"].to_dict()}
            for e in diff["escalated"]
        ],
        "improved": [
            {"baseline": e["baseline"].to_dict(), "current": e["current"].to_dict()}
            for e in diff["improved"]
        ],
        "unchanged": [f.to_dict() for f in diff["unchanged"]],
    }
    Path(path).write_text(json.dumps(serialisable, indent=2, ensure_ascii=False), encoding="utf-8")


# ── internal helpers ──────────────────────────────────────────────────────────

def _build_report(
    findings: list[Finding],
    domain: str = "",
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    counts = {sev.name: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.name] += 1

    return {
        "meta": {
            "tool":      "maul",
            "version":   __version__,
            "generated": datetime.now(tz=timezone.utc).isoformat(),
            "domain":    domain,
            **(meta or {}),
        },
        "summary": {
            "total":    len(findings),
            "by_severity": counts,
        },
        "findings": [f.to_dict() for f in findings],
    }


def _finding_key(f: Finding) -> str:
    """Stable identity key for a finding across scans."""
    return f"{f.module}::{f.check}"


def _findings_by_key(findings: list[Finding]) -> dict[str, Finding]:
    result: dict[str, Finding] = {}
    for f in findings:
        key = _finding_key(f)
        # If duplicate keys exist, keep the higher-severity one
        if key not in result or f.severity > result[key].severity:
            result[key] = f
    return result
