# Thin re-export — prefer importing SEVERITY_STYLES from reporting.console directly.
from maul.reporting.finding import Severity

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}
