"""HTML report writer — produces a self-contained single-file report."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from maul import __version__
from maul.reporting.finding import Finding, Severity

_SEV_COLOR = {
    Severity.CRITICAL: "#c0392b",
    Severity.HIGH:     "#e67e22",
    Severity.MEDIUM:   "#f1c40f",
    Severity.LOW:      "#2980b9",
    Severity.INFO:     "#27ae60",
}

_SEV_BG = {
    Severity.CRITICAL: "#fdf0ef",
    Severity.HIGH:     "#fef5ec",
    Severity.MEDIUM:   "#fefde7",
    Severity.LOW:      "#eaf4fb",
    Severity.INFO:     "#eafaf1",
}

_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Maul Report — {domain}</title>
<style>
  :root {{
    --bg: #f5f6fa;
    --card: #ffffff;
    --border: #dde1ea;
    --text: #2d3436;
    --muted: #636e72;
    --code-bg: #f0f1f3;
    --shadow: 0 1px 4px rgba(0,0,0,.08);
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px; line-height: 1.6;
    background: var(--bg); color: var(--text);
    padding: 24px 16px 60px;
  }}
  a {{ color: #2980b9; }}

  /* ── header ── */
  .report-header {{
    background: #1e272e; color: #ecf0f1;
    border-radius: 8px; padding: 24px 32px; margin-bottom: 24px;
  }}
  .report-header h1 {{ font-size: 22px; font-weight: 700; letter-spacing: .5px; }}
  .report-header .meta {{ font-size: 12px; color: #b2bec3; margin-top: 6px; }}

  /* ── summary bar ── */
  .summary-bar {{
    display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px;
  }}
  .sev-badge {{
    display: flex; align-items: center; gap: 8px;
    background: var(--card); border: 1px solid var(--border);
    border-radius: 6px; padding: 10px 18px;
    box-shadow: var(--shadow); cursor: pointer;
    transition: opacity .15s;
    user-select: none;
  }}
  .sev-badge.inactive {{ opacity: .35; }}
  .sev-dot {{ width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }}
  .sev-count {{ font-size: 20px; font-weight: 700; }}
  .sev-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }}

  /* ── controls ── */
  .controls {{
    display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; align-items: center;
  }}
  .controls input[type=search] {{
    flex: 1; min-width: 200px; padding: 8px 14px;
    border: 1px solid var(--border); border-radius: 6px;
    font-size: 14px; background: var(--card);
    outline: none;
  }}
  .controls input[type=search]:focus {{ border-color: #2980b9; }}
  .controls select {{
    padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px;
    font-size: 14px; background: var(--card); cursor: pointer;
  }}
  .result-count {{ font-size: 12px; color: var(--muted); white-space: nowrap; }}

  /* ── finding card ── */
  .finding {{
    background: var(--card); border: 1px solid var(--border);
    border-left: 4px solid var(--sev-color);
    border-radius: 6px; margin-bottom: 12px;
    box-shadow: var(--shadow); overflow: hidden;
  }}
  .finding-header {{
    display: flex; align-items: flex-start; gap: 12px;
    padding: 14px 16px; cursor: pointer;
    user-select: none;
  }}
  .finding-header:hover {{ background: #f8f9fa; }}
  .sev-pill {{
    flex-shrink: 0; font-size: 11px; font-weight: 700;
    padding: 3px 8px; border-radius: 12px; color: #fff;
    text-transform: uppercase; letter-spacing: .4px; margin-top: 2px;
  }}
  .finding-title {{ flex: 1; font-weight: 600; font-size: 14px; }}
  .finding-meta {{ font-size: 11px; color: var(--muted); white-space: nowrap; margin-top: 3px; }}
  .chevron {{ flex-shrink: 0; transition: transform .2s; color: var(--muted); margin-top: 3px; }}
  .finding.open .chevron {{ transform: rotate(90deg); }}

  .finding-body {{ display: none; padding: 0 16px 16px; }}
  .finding.open .finding-body {{ display: block; }}

  .section-label {{
    font-size: 11px; font-weight: 700; text-transform: uppercase;
    color: var(--muted); letter-spacing: .6px; margin: 14px 0 6px;
  }}
  .description {{ color: #2d3436; }}
  .detail-block {{
    background: var(--code-bg); border-radius: 4px;
    padding: 10px 12px; font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 12px; white-space: pre-wrap; word-break: break-word;
    max-height: 280px; overflow-y: auto;
  }}
.refs a {{ display: inline-block; margin-right: 12px; font-size: 12px; }}

  .no-results {{
    text-align: center; padding: 40px; color: var(--muted); font-size: 15px;
  }}

  /* ── module section ── */
  .module-section {{ margin-bottom: 32px; }}
  .module-heading {{
    font-size: 13px; font-weight: 700; text-transform: uppercase;
    letter-spacing: .8px; color: var(--muted);
    padding: 8px 0; margin-bottom: 8px;
    border-bottom: 2px solid var(--border);
  }}
</style>
</head>
<body>

<div class="report-header">
  <h1>&#128512; Maul — AD Security Assessment</h1>
  <div class="meta">
    Domain: <strong>{domain}</strong> &nbsp;|&nbsp;
    Generated: {generated} &nbsp;|&nbsp;
    maul v{version} &nbsp;|&nbsp;
    {total} finding(s)
  </div>
</div>

<div class="summary-bar" id="summary-bar">
{summary_badges}
</div>

<div class="controls">
  <input type="search" id="search-box" placeholder="Search findings…" oninput="applyFilters()">
  <select id="module-filter" onchange="applyFilters()">
    <option value="">All modules</option>
{module_options}
  </select>
  <span class="result-count" id="result-count"></span>
</div>

<div id="findings-container">
{findings_html}
</div>

<p class="no-results" id="no-results" style="display:none">No findings match the current filters.</p>

<script>
const SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
let activeSevs = new Set(SEV_ORDER);

function toggleSev(sev) {{
  if (activeSevs.has(sev)) {{
    activeSevs.delete(sev);
  }} else {{
    activeSevs.add(sev);
  }}
  document.querySelectorAll('.sev-badge').forEach(b => {{
    b.classList.toggle('inactive', !activeSevs.has(b.dataset.sev));
  }});
  applyFilters();
}}

function applyFilters() {{
  const q     = document.getElementById('search-box').value.toLowerCase();
  const modF  = document.getElementById('module-filter').value;
  let visible = 0;

  document.querySelectorAll('.finding').forEach(el => {{
    const sev    = el.dataset.sev;
    const mod    = el.dataset.mod;
    const text   = el.textContent.toLowerCase();
    const show   = activeSevs.has(sev)
                && (!modF || mod === modF)
                && (!q    || text.includes(q));
    el.style.display = show ? '' : 'none';
    if (show) visible++;
  }});

  // Show/hide module headings
  document.querySelectorAll('.module-section').forEach(sec => {{
    const anyVisible = [...sec.querySelectorAll('.finding')]
      .some(f => f.style.display !== 'none');
    sec.style.display = anyVisible ? '' : 'none';
  }});

  document.getElementById('result-count').textContent =
    visible + ' finding' + (visible !== 1 ? 's' : '');
  document.getElementById('no-results').style.display = visible ? 'none' : '';
}}

function toggleFinding(el) {{
  el.closest('.finding').classList.toggle('open');
}}

// Initialise count
applyFilters();
</script>
</body>
</html>
"""


def write_html(
    findings: list[Finding],
    path: str | Path,
    *,
    domain: str = "",
    title: str = "",
) -> None:
    """Write a self-contained HTML report."""
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1

    summary_badges = _render_summary_badges(counts)
    module_options = _render_module_options(findings)
    findings_html  = _render_findings(findings)

    output = _TEMPLATE.format(
        domain=html.escape(domain or "(unknown)"),
        generated=generated,
        version=html.escape(__version__),
        total=len(findings),
        summary_badges=summary_badges,
        module_options=module_options,
        findings_html=findings_html,
    )
    Path(path).write_text(output, encoding="utf-8")


def write_diff_html(diff: dict, path: str | Path) -> None:
    """Write a self-contained HTML diff report."""
    all_findings: list[Finding] = (
        diff.get("new", [])
        + [e["current"] for e in diff.get("escalated", [])]
        + [e["current"] for e in diff.get("improved", [])]
    )
    # Tag findings with diff status for display
    diff_tags: dict[str, str] = {}
    for f in diff.get("new", []):
        diff_tags[f"{f.module}::{f.check}"] = "NEW"
    for e in diff.get("escalated", []):
        diff_tags[f"{e['current'].module}::{e['current'].check}"] = "ESCALATED"
    for e in diff.get("improved", []):
        diff_tags[f"{e['current'].module}::{e['current'].check}"] = "IMPROVED"

    bl_meta = diff.get("baseline_meta", {})
    cu_meta = diff.get("current_meta", {})
    domain  = cu_meta.get("domain", "")

    write_html(
        all_findings,
        path,
        domain=domain,
        title=(
            f"Diff — {bl_meta.get('generated','?')} vs "
            f"{cu_meta.get('generated','?')}"
        ),
    )


# ── rendering helpers ─────────────────────────────────────────────────────────

def _render_summary_badges(counts: dict[Severity, int]) -> str:
    parts: list[str] = []
    for sev in sorted(Severity, reverse=True):
        color = _SEV_COLOR[sev]
        parts.append(
            f'  <div class="sev-badge" data-sev="{sev.name}" '
            f'onclick="toggleSev(\'{sev.name}\')">'
            f'<span class="sev-dot" style="background:{color}"></span>'
            f'<span class="sev-count">{counts[sev]}</span>'
            f'<span class="sev-label">{sev.name}</span>'
            f'</div>'
        )
    return "\n".join(parts)


def _render_module_options(findings: list[Finding]) -> str:
    modules = sorted({f.module for f in findings})
    return "\n".join(
        f'    <option value="{html.escape(m)}">{html.escape(m)}</option>'
        for m in modules
    )


def _render_findings(findings: list[Finding]) -> str:
    # Group by module, sort modules alphabetically, findings by severity desc
    modules: dict[str, list[Finding]] = {}
    for f in findings:
        modules.setdefault(f.module, []).append(f)

    sections: list[str] = []
    for mod in sorted(modules):
        mod_findings = sorted(modules[mod], key=lambda x: x.severity, reverse=True)
        cards = "\n".join(_render_card(f) for f in mod_findings)
        sections.append(
            f'<div class="module-section">'
            f'<div class="module-heading">{html.escape(mod)}</div>'
            f'{cards}'
            f'</div>'
        )
    return "\n".join(sections)


def _render_card(f: Finding) -> str:
    sev_color = _SEV_COLOR[f.severity]
    details_html = _render_details(f.details)
    refs_html = ""
    if f.references:
        links = " ".join(
            f'<a href="{html.escape(r)}" target="_blank" rel="noopener">{html.escape(r)}</a>'
            for r in f.references
        )
        refs_html = f'<div class="section-label">References</div><div class="refs">{links}</div>'

    return f"""\
<div class="finding" data-sev="{f.severity.name}" data-mod="{html.escape(f.module)}"
     style="--sev-color:{sev_color}">
  <div class="finding-header" onclick="toggleFinding(this)">
    <span class="sev-pill" style="background:{sev_color}">{f.severity.name}</span>
    <div style="flex:1">
      <div class="finding-title">{html.escape(f.title)}</div>
      <div class="finding-meta">{html.escape(f.module)} · {html.escape(f.check)}</div>
    </div>
    <span class="chevron">&#9654;</span>
  </div>
  <div class="finding-body">
    <div class="section-label">Description</div>
    <div class="description">{html.escape(f.description)}</div>
    {details_html}
    {refs_html}
  </div>
</div>"""


def _render_details(details: dict) -> str:
    if not details:
        return ""

    parts = ['<div class="section-label">Details</div>']
    for key, value in details.items():
        label = html.escape(str(key).replace("_", " ").title())
        if isinstance(value, list):
            items = "\n".join(html.escape(str(v)) for v in value[:50])
            if len(value) > 50:
                items += f"\n… and {len(value) - 50} more"
            parts.append(
                f'<div style="margin-bottom:6px"><strong>{label}</strong>'
                f'<div class="detail-block">{items}</div></div>'
            )
        elif isinstance(value, dict):
            inner = "\n".join(
                f"{html.escape(str(k))}: {html.escape(str(v))}"
                for k, v in value.items()
            )
            parts.append(
                f'<div style="margin-bottom:6px"><strong>{label}</strong>'
                f'<div class="detail-block">{inner}</div></div>'
            )
        else:
            parts.append(
                f'<div style="margin-bottom:4px">'
                f'<strong>{label}:</strong> {html.escape(str(value))}</div>'
            )
    return "\n".join(parts)
