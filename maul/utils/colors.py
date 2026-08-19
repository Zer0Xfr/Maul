# Thin re-export — prefer importing SEVERITY_STYLES from reporting.console directly.
from maul.reporting.finding import Severity

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.PWNED: "bold red",
    Severity.LIKELY: "red",
    Severity.POSSIBLE: "yellow",
    Severity.HARDENED: "cyan",
    Severity.RECON: "dim white",
}
