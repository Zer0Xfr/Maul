"""Computer module — LAPS deployment, outdated OS detection, infrastructure server discovery."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from maul.core.ldap_client import get_attr, get_attr_first
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.parsers import filetime_to_datetime

log = logging.getLogger(__name__)

# OS strings that indicate end-of-life Windows versions
_EOL_OS_PATTERNS = [
    (re.compile(r"Windows XP",             re.I), "Windows XP",            "EOL since 2014"),
    (re.compile(r"Windows Vista",          re.I), "Windows Vista",         "EOL since 2017"),
    (re.compile(r"Windows 7",              re.I), "Windows 7",             "EOL since 2020"),
    (re.compile(r"Windows 8(?!\.1)",       re.I), "Windows 8",             "EOL since 2016"),
    (re.compile(r"Windows 8\.1",           re.I), "Windows 8.1",           "EOL since 2023"),
    (re.compile(r"Windows Server 2003",    re.I), "Windows Server 2003",   "EOL since 2015"),
    (re.compile(r"Windows Server 2008",    re.I), "Windows Server 2008",   "EOL since 2020"),
    (re.compile(r"Windows Server 2012",    re.I), "Windows Server 2012",   "EOL since 2023"),
]

# SPNs that identify common infrastructure roles
_INFRA_SPN_PATTERNS = [
    (re.compile(r"^MSSQLSvc/",   re.I), "MSSQL",        "Microsoft SQL Server"),
    (re.compile(r"^exchangeMDB/",re.I), "Exchange",     "Microsoft Exchange"),
    (re.compile(r"^WSMAN/",      re.I), "WinRM",        "Windows Remote Management"),
    (re.compile(r"^http/",       re.I), "HTTP",         "Web Server (IIS)"),
    (re.compile(r"^vmware",      re.I), "VMware",       "VMware"),
    (re.compile(r"^ldap/",       re.I), "LDAP",         "Domain Controller"),
    (re.compile(r"^GC/",         re.I), "GlobalCatalog","Domain Controller (GC)"),
    (re.compile(r"^Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/", re.I), "DFSR", "DFS Replication"),
]


@register
class ComputerModule(ModuleBase):
    name = "computer"
    description = "LAPS deployment, outdated OS versions, infrastructure server discovery"
    opsec_safe = True

    def run(self) -> list[Finding]:
        computers = self._enumerate_computers()
        if not computers:
            self.add_finding(
                check="ComputerPresent",
                severity=Severity.RECON,
                title="No computer objects found",
                description="No computer objects returned from LDAP.",
            )
            return self.findings

        self.add_finding(
            check="ComputerPresent",
            severity=Severity.RECON,
            title=f"Computer objects: {len(computers)}",
            description=f"Found {len(computers)} computer object(s) in the domain.",
        )

        self._check_laps(computers)
        self._check_outdated_os(computers)
        self._check_infrastructure_servers(computers)
        self._check_stale_computers(computers)

        return self.findings

    # ── enumeration ───────────────────────────────────────────────────────────

    def _enumerate_computers(self) -> list[dict]:
        return self.conn.ldap_search(
            "(objectClass=computer)",
            attributes=[
                "sAMAccountName", "dNSHostName", "operatingSystem",
                "operatingSystemVersion", "distinguishedName",
                "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-EncryptedPassword", "msLAPS-Password",
                "msLAPS-PasswordExpirationTime",
                "servicePrincipalName", "userAccountControl",
                "lastLogonTimestamp", "whenCreated",
            ],
        )

    # ── LAPS check ────────────────────────────────────────────────────────────

    def _check_laps(self, computers: list[dict]) -> None:
        laps_schema_present = self._laps_schema_present()

        if not laps_schema_present:
            self.add_finding(
                check="LAPS",
                severity=Severity.POSSIBLE,
                title="LAPS not deployed (schema attributes absent)",
                description=(
                    "Neither legacy LAPS (ms-Mcs-AdmPwd) nor Windows LAPS (msLAPS-Password) "
                    "schema attributes are present in the domain. Local Administrator passwords "
                    "are not managed centrally, making lateral movement trivially easy if a "
                    "single password is reused across machines."
                ),
                references=["https://attack.mitre.org/techniques/T1078/002/"],
            )
            return

        # Schema present — check coverage
        total = len(computers)
        laps_covered = 0
        no_laps: list[str] = []

        for c in computers:
            # Skip disabled computers
            uac = int(get_attr_first(c, "userAccountControl") or 0)
            if uac & 0x2:
                total -= 1
                continue

            has_legacy  = bool(get_attr_first(c, "ms-Mcs-AdmPwd") or
                               get_attr_first(c, "ms-Mcs-AdmPwdExpirationTime"))
            has_new     = bool(get_attr_first(c, "msLAPS-Password") or
                               get_attr_first(c, "msLAPS-EncryptedPassword") or
                               get_attr_first(c, "msLAPS-PasswordExpirationTime"))

            if has_legacy or has_new:
                laps_covered += 1
            else:
                name = str(get_attr_first(c, "sAMAccountName") or get_attr_first(c, "dNSHostName") or "?")
                no_laps.append(name)

        if total == 0:
            return

        coverage_pct = (laps_covered / total) * 100

        if laps_covered == total:
            self.add_finding(
                check="LAPS",
                severity=Severity.RECON,
                title=f"LAPS deployed: {laps_covered}/{total} computers covered (100%)",
                description="All enabled computer accounts have LAPS password attributes populated.",
            )
        else:
            sev = Severity.POSSIBLE if coverage_pct < 50 else Severity.POSSIBLE
            self.add_finding(
                check="LAPS",
                severity=sev,
                title=f"LAPS partial coverage: {laps_covered}/{total} computers ({coverage_pct:.0f}%)",
                description=(
                    f"LAPS schema is present but only {laps_covered} of {total} enabled computers "
                    f"have LAPS attributes populated. {len(no_laps)} computer(s) have no managed "
                    "local Administrator password — these may share a common password."
                ),
                details={"computers_without_laps": no_laps[:50]},
            )

    def _laps_schema_present(self) -> bool:
        """Check if LAPS schema attributes exist."""
        for attr_name in ("ms-Mcs-AdmPwd", "msLAPS-Password"):
            cn = attr_name.lower().replace("-", "")
            entries = self.conn.ldap_search(
                f"(lDAPDisplayName={attr_name})",
                attributes=["lDAPDisplayName"],
                base=self.conn.schema_dn,
                scope="ONE",
            )
            if entries:
                return True
        return False

    # ── outdated OS ───────────────────────────────────────────────────────────

    def _check_outdated_os(self, computers: list[dict]) -> None:
        eol_found: dict[str, list[str]] = {}

        for c in computers:
            uac = int(get_attr_first(c, "userAccountControl") or 0)
            if uac & 0x2:
                continue

            os_str = str(get_attr_first(c, "operatingSystem") or "")
            if not os_str:
                continue

            hostname = str(get_attr_first(c, "dNSHostName") or get_attr_first(c, "sAMAccountName") or "?")

            for pattern, label, _eol_date in _EOL_OS_PATTERNS:
                if pattern.search(os_str):
                    eol_found.setdefault(label, []).append(hostname)
                    break

        if not eol_found:
            self.add_finding(
                check="OutdatedOS",
                severity=Severity.RECON,
                title="No end-of-life operating systems detected",
                description="All computer objects report a supported operating system.",
            )
            return

        total_eol = sum(len(v) for v in eol_found.values())
        # Any EOL server OS is HIGH; EOL workstations are MEDIUM
        server_eol = [k for k in eol_found if "Server" in k]
        sev = Severity.POSSIBLE if server_eol else Severity.POSSIBLE

        self.add_finding(
            check="OutdatedOS",
            severity=sev,
            title=f"End-of-life operating systems: {total_eol} computer(s)",
            description=(
                "The following end-of-life operating systems were found in the domain. "
                "EOL systems no longer receive security patches and are high-value targets "
                "for known exploits (EternalBlue, PrintNightmare, etc.)."
            ),
            details={
                "eol_breakdown": {label: hosts for label, hosts in eol_found.items()},
            },
            references=["https://attack.mitre.org/techniques/T1210/"],
        )

    # ── infrastructure servers ────────────────────────────────────────────────

    def _check_infrastructure_servers(self, computers: list[dict]) -> None:
        infra: dict[str, list[str]] = {}

        for c in computers:
            spns = get_attr(c, "servicePrincipalName") or []
            hostname = str(get_attr_first(c, "dNSHostName") or get_attr_first(c, "sAMAccountName") or "?")

            for spn in spns:
                spn_str = str(spn)
                for pattern, role, _desc in _INFRA_SPN_PATTERNS:
                    if pattern.search(spn_str):
                        if role not in ("LDAP", "GlobalCatalog", "DFSR"):
                            infra.setdefault(role, set()).add(hostname)
                        break

        if not infra:
            return

        self.add_finding(
            check="InfrastructureServers",
            severity=Severity.RECON,
            title=f"Infrastructure servers discovered: {sum(len(v) for v in infra.values())} host(s)",
            description="Infrastructure servers identified via SPN enumeration.",
            details={
                role: sorted(hosts) for role, hosts in infra.items()
            },
        )

    # ── stale computer accounts ───────────────────────────────────────────────

    def _check_stale_computers(self, computers: list[dict]) -> None:
        cutoff_days = 90
        now = datetime.now(tz=timezone.utc)
        stale: list[str] = []

        for c in computers:
            uac = int(get_attr_first(c, "userAccountControl") or 0)
            if uac & 0x2:
                continue

            raw_ts = get_attr_first(c, "lastLogonTimestamp")
            if raw_ts is None:
                continue
            try:
                ts = int(raw_ts)
            except (ValueError, TypeError):
                continue

            last_logon = filetime_to_datetime(ts)
            if last_logon is None:
                continue

            delta = now - last_logon
            if delta.days > cutoff_days:
                hostname = str(get_attr_first(c, "dNSHostName") or get_attr_first(c, "sAMAccountName") or "?")
                stale.append(hostname)

        if not stale:
            self.add_finding(
                check="StaleComputers",
                severity=Severity.RECON,
                title=f"No stale computer accounts (>{cutoff_days} days inactive)",
                description=f"All enabled computers have logged in within the last {cutoff_days} days.",
            )
            return

        self.add_finding(
            check="StaleComputers",
            severity=Severity.HARDENED,
            title=f"Stale computer accounts: {len(stale)} (>{cutoff_days} days inactive)",
            description=(
                f"{len(stale)} enabled computer account(s) have not authenticated in over "
                f"{cutoff_days} days. Stale accounts may represent decommissioned systems "
                "that could be hijacked if their passwords haven't changed recently."
            ),
            details={"stale_computers": stale[:50]},
        )
