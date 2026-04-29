from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from maul.reporting.finding import Finding, Severity

console = Console(highlight=False)

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: " MED",
    Severity.LOW: " LOW",
    Severity.INFO: "INFO",
}

_BANNER = """\
[bold red]
  ███╗   ███╗ █████╗ ██╗   ██╗██╗
  ████╗ ████║██╔══██╗██║   ██║██║
  ██╔████╔██║███████║██║   ██║██║
  ██║╚██╔╝██║██╔══██║██║   ██║██║
  ██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝[/bold red]
[dim]  AD privilege escalation assessment — Linux edition    v0.1[/dim]
"""


def print_banner() -> None:
    console.print(_BANNER)


def print_section(title: str) -> None:
    console.print(f"\n[bold blue]━━━  {title}  ━━━[/bold blue]")


def print_finding(finding: Finding) -> None:
    style = _SEVERITY_STYLE[finding.severity]
    label = _SEVERITY_LABEL[finding.severity]

    header = Text()
    header.append(f"[{label}] ", style=style)
    header.append(f"{finding.module} / {finding.check}", style="bold")

    console.print(header)
    console.print(f"  [bold]{finding.title}[/bold]")
    console.print(f"  {finding.description}")

    if finding.details:
        for key, val in finding.details.items():
            if isinstance(val, list):
                console.print(f"  [dim]{key}:[/dim]")
                for item in val[:20]:
                    console.print(f"    • {item}")
                if len(val) > 20:
                    console.print(f"    … and {len(val) - 20} more")
            else:
                console.print(f"  [dim]{key}:[/dim] {val}")

    console.print()


def print_findings_summary(findings: list[Finding]) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    table = Table(title="Findings Summary", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for sev in sorted(Severity, reverse=True):
        if counts[sev]:
            table.add_row(
                Text(sev.name, style=_SEVERITY_STYLE[sev]),
                str(counts[sev]),
            )

    table.add_row("TOTAL", str(len(findings)), style="bold")
    console.print(table)


def print_findings_table(findings: list[Finding]) -> None:
    if not findings:
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Sev", width=5)
    table.add_column("Module", width=12)
    table.add_column("Check", width=20)
    table.add_column("Title")

    for f in sorted(findings, key=lambda x: x.severity, reverse=True):
        style = _SEVERITY_STYLE[f.severity]
        table.add_row(
            Text(f.severity.name[:4], style=style),
            f.module,
            f.check,
            f.title,
        )

    console.print(table)


def print_error(msg: str) -> None:
    console.print(f"[bold red][!][/bold red] {msg}")


def print_warning(msg: str) -> None:
    console.print(f"[yellow][!][/yellow] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[dim][*][/dim] {msg}")


def print_success(msg: str) -> None:
    console.print(f"[green][+][/green] {msg}")
