"""Plain-text report writer."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from maul import __version__
from maul.reporting.finding import Finding, Severity

_SEV_LABEL = {
    Severity.PWNED:    "[PWNED   ]",
    Severity.LIKELY:   "[LIKELY  ]",
    Severity.POSSIBLE: "[POSSIBLE]",
    Severity.HARDENED: "[HARDENED]",
    Severity.RECON:    "[RECON   ]",
}

_LINE = "=" * 80
_DASH = "-" * 80


def write_text(
    findings: list[Finding],
    path: str | Path,
    *,
    domain: str = "",
) -> None:
    """Write a structured plain-text report."""
    lines = _render_report(findings, domain=domain)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_diff_text(diff: dict, path: str | Path) -> None:
    """Write a plain-text diff report."""
    lines = _render_diff(diff)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── rendering ─────────────────────────────────────────────────────────────────

def _render_report(findings: list[Finding], domain: str = "") -> list[str]:
    lines: list[str] = []

    lines += [
        _LINE,
        "  MAUL — Active Directory Security Assessment Report",
        _LINE,
        f"  Tool     : maul v{__version__}",
        f"  Domain   : {domain or '(unknown)'}",
        f"  Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"  Findings : {len(findings)}",
        _LINE,
        "",
    ]

    # Summary counts
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    lines.append("SUMMARY")
    lines.append(_DASH)
    for sev in sorted(Severity, reverse=True):
        if counts[sev]:
            lines.append(f"  {_SEV_LABEL[sev]}  {counts[sev]}")
    lines.append("")

    # Group by module
    modules: dict[str, list[Finding]] = {}
    for f in findings:
        modules.setdefault(f.module, []).append(f)

    for module_name, mod_findings in modules.items():
        lines.append(_LINE)
        lines.append(f"  MODULE: {module_name.upper()}")
        lines.append(_LINE)

        # Sort by severity descending within module
        for f in sorted(mod_findings, key=lambda x: x.severity, reverse=True):
            lines += _render_finding(f)

    lines.append(_LINE)
    lines.append("  END OF REPORT")
    lines.append(_LINE)

    return lines


def _render_finding(f: Finding) -> list[str]:
    lines: list[str] = []
    label = _SEV_LABEL[f.severity]

    lines.append("")
    lines.append(f"{label} [{f.check}] {f.title}")
    lines.append(_DASH)
    lines.append(f"  {f.description}")

    if f.details:
        lines.append("")
        lines.append("  Details:")
        for key, value in f.details.items():
            if isinstance(value, list):
                lines.append(f"    {key}:")
                for item in value[:30]:
                    lines.append(f"      - {item}")
                if len(value) > 30:
                    lines.append(f"      ... and {len(value) - 30} more")
            elif isinstance(value, dict):
                lines.append(f"    {key}:")
                for k2, v2 in value.items():
                    if isinstance(v2, list):
                        lines.append(f"      {k2}:")
                        for item in v2[:20]:
                            lines.append(f"        - {item}")
                    else:
                        lines.append(f"      {k2}: {v2}")
            else:
                lines.append(f"    {key}: {value}")

    if f.references:
        lines.append("")
        lines.append("  References:")
        for ref in f.references:
            lines.append(f"    - {ref}")

    return lines


def _render_diff(diff: dict) -> list[str]:
    lines: list[str] = []

    bl_meta = diff.get("baseline_meta", {})
    cu_meta = diff.get("current_meta", {})

    lines += [
        _LINE,
        "  MAUL — Report Diff",
        _LINE,
        f"  Baseline : {bl_meta.get('generated', '?')} — {bl_meta.get('domain', '?')}",
        f"  Current  : {cu_meta.get('generated', '?')} — {cu_meta.get('domain', '?')}",
        f"  Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        _LINE,
        "",
        "SUMMARY",
        _DASH,
        f"  New findings      : {len(diff['new'])}",
        f"  Resolved findings : {len(diff['resolved'])}",
        f"  Escalated         : {len(diff['escalated'])}",
        f"  Improved          : {len(diff['improved'])}",
        f"  Unchanged         : {len(diff['unchanged'])}",
        "",
    ]

    if diff["new"]:
        lines.append(_LINE)
        lines.append("  NEW FINDINGS")
        lines.append(_LINE)
        for f in sorted(diff["new"], key=lambda x: x.severity, reverse=True):
            lines += _render_finding(f)

    if diff["resolved"]:
        lines.append(_LINE)
        lines.append("  RESOLVED FINDINGS")
        lines.append(_LINE)
        for f in diff["resolved"]:
            lines.append(f"  {_SEV_LABEL[f.severity]} [{f.check}] {f.title}")

    if diff["escalated"]:
        lines.append(_LINE)
        lines.append("  ESCALATED (severity increased)")
        lines.append(_LINE)
        for e in diff["escalated"]:
            bl, cu = e["baseline"], e["current"]
            lines.append(
                f"  {_SEV_LABEL[bl.severity]} → {_SEV_LABEL[cu.severity]}  "
                f"[{cu.check}] {cu.title}"
            )

    if diff["improved"]:
        lines.append(_LINE)
        lines.append("  IMPROVED (severity decreased)")
        lines.append(_LINE)
        for e in diff["improved"]:
            bl, cu = e["baseline"], e["current"]
            lines.append(
                f"  {_SEV_LABEL[bl.severity]} → {_SEV_LABEL[cu.severity]}  "
                f"[{cu.check}] {cu.title}"
            )

    lines.append(_LINE)
    lines.append("  END OF DIFF REPORT")
    lines.append(_LINE)

    return lines


def _wrap(text: str, width: int = 76, indent: str = "") -> list[str]:
    """Simple word-wrap."""
    words = text.split()
    lines: list[str] = []
    current = indent
    for word in words:
        if len(current) + len(word) + 1 > width and current.strip():
            lines.append(current.rstrip())
            current = indent + word + " "
        else:
            current += word + " "
    if current.strip():
        lines.append(current.rstrip())
    return lines or [indent]
