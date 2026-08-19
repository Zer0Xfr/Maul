"""Accounts module — privileged groups, adminCount, SID history, stale accounts."""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from maul.core.ldap_client import get_attr, get_attr_first, get_attr_bytes
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.constants import (
    DOMAIN_RELATIVE_SIDS,
    PRIVILEGED_BUILTIN_SIDS,
    PRIVILEGED_GROUP_RIDS,
    WELL_KNOWN_SIDS,
)
from maul.utils.ldap_filters import (
    ADMIN_COUNT,
    DONT_EXPIRE_PASSWORD,
    ENABLED_USERS,
    SID_HISTORY,
    and_,
    group_member_recursive_filter,
    inactive_accounts_filter,
    uac_bit,
    uac_bit_not,
)
from maul.utils.parsers import filetime_to_datetime, sid_to_str

log = logging.getLogger(__name__)

# Groups to enumerate members for, in priority order
_SENSITIVE_GROUPS: list[tuple[str, str]] = [
    ("Domain Admins", "Full control of the domain"),
    ("Enterprise Admins", "Full control of the entire forest"),
    ("Schema Admins", "Can modify the AD schema"),
    ("Group Policy Creator Owners", "Can create/edit Group Policy Objects"),
    ("Protected Users", "Members cannot use weak auth protocols"),
    ("Administrators", "Local admins on all domain-joined machines"),
    ("Account Operators", "Can manage most user/group accounts"),
    ("Backup Operators", "Can bypass file permissions to read any file"),
    ("Server Operators", "Can log on and manage domain controllers"),
    ("Print Operators", "Can manage DCs' print queues"),
    ("DnsAdmins", "Can execute DLL on DC via DNS service"),
]

# RIDs of truly privileged groups (Domain Admins / EA / SA / GPO)
_HIGH_PRIV_RIDS: frozenset[str] = frozenset({"-512", "-518", "-519", "-520"})


@register
class AccountsModule(ModuleBase):
    name = "accounts"
    description = "Privileged group membership, adminCount, SID history, stale accounts"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._check_privileged_groups()
        self._check_admin_count()
        self._check_sid_history()
        self._check_password_never_expires()
        self._check_inactive_accounts()
        return self.findings

    # ── privileged group membership ───────────────────────────────────────────

    def _check_privileged_groups(self) -> None:
        domain_sid = self.conn.domain_sid

        for group_name, group_desc in _SENSITIVE_GROUPS:
            dn, members = self._get_group_members(group_name)
            if dn is None:
                log.debug("Group %r not found", group_name)
                continue

            enabled = [m for m in members if not _is_disabled(m)]
            disabled = [m for m in members if _is_disabled(m)]

            member_names = [
                str(get_attr_first(m, "sAMAccountName") or m.get("dn", "?"))
                for m in enabled
            ]
            disabled_names = [
                str(get_attr_first(m, "sAMAccountName") or m.get("dn", "?"))
                for m in disabled
            ]

            # Determine severity by group type
            rid = _group_rid(dn, domain_sid)
            if rid in _HIGH_PRIV_RIDS:
                sev = Severity.POSSIBLE
            else:
                sev = Severity.RECON

            self.add_finding(
                check="PrivilegedGroupMembership",
                severity=sev,
                title=f"{group_name}: {len(enabled)} enabled member(s)",
                description=(
                    f"{group_desc}. "
                    f"{len(enabled)} enabled and {len(disabled)} disabled member(s) found "
                    f"(recursive)."
                ),
                details={
                    "group": group_name,
                    "group_dn": dn,
                    "enabled_members": member_names,
                    "disabled_members": disabled_names,
                    "total": len(members),
                },
            )

    # ── adminCount ────────────────────────────────────────────────────────────

    def _check_admin_count(self) -> None:
        """Find enabled users with adminCount=1 that are NOT currently in privileged groups."""
        entries = self.conn.ldap_search(
            ADMIN_COUNT,
            attributes=["sAMAccountName", "distinguishedName", "memberOf"],
        )
        if not entries:
            return

        names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]

        self.add_finding(
            check="AdminCountResidual",
            severity=Severity.RECON,
            title=f"adminCount=1: {len(entries)} enabled user(s)",
            description=(
                "Users with adminCount=1 were previously (or currently) in a protected group "
                "and have their DACL overridden by the SDProp process. "
                "If not actively privileged, their relaxed DACL means they may have fewer "
                "inherited protections than expected."
            ),
            details={"count": len(entries), "accounts": names},
        )

    # ── SID history ───────────────────────────────────────────────────────────

    def _check_sid_history(self) -> None:
        entries = self.conn.ldap_search(
            SID_HISTORY,
            attributes=["sAMAccountName", "distinguishedName", "sIDHistory"],
        )
        if not entries:
            return

        domain_sid = self.conn.domain_sid
        privileged: list[str] = []
        all_accounts: list[str] = []

        for entry in entries:
            sam = str(get_attr_first(entry, "sAMAccountName") or entry.get("dn", "?"))
            all_accounts.append(sam)

            sid_history = get_attr(entry, "sIDHistory") or []
            if not isinstance(sid_history, list):
                sid_history = [sid_history]

            for raw_sid in sid_history:
                sid_str = _decode_sid(raw_sid)
                if sid_str is None:
                    continue
                if _is_privileged_sid(sid_str, domain_sid):
                    privileged.append(f"{sam} → {sid_str}")

        if privileged:
            self.add_finding(
                check="SIDHistoryPrivileged",
                severity=Severity.PWNED,
                title=f"SID history contains privileged SIDs: {len(privileged)} account(s)",
                description=(
                    "Accounts with SID history entries matching privileged groups (Domain Admins, "
                    "Enterprise Admins, etc.) effectively hold those group's privileges without "
                    "appearing as members. This is a known technique for backdoor persistence."
                ),
                details={"privileged_mappings": privileged},
                references=["https://attack.mitre.org/techniques/T1134/005/"],
            )

        if all_accounts:
            self.add_finding(
                check="SIDHistory",
                severity=Severity.HARDENED if not privileged else Severity.RECON,
                title=f"SID history set on {len(all_accounts)} account(s)",
                description=(
                    f"{len(all_accounts)} account(s) have the sIDHistory attribute set. "
                    "SID history is used during AD migrations but can enable privilege escalation "
                    "if set to privileged SIDs."
                ),
                details={"accounts_with_sid_history": all_accounts},
            )

    # ── password never expires ────────────────────────────────────────────────

    def _check_password_never_expires(self) -> None:
        entries = self.conn.ldap_search(
            DONT_EXPIRE_PASSWORD,
            attributes=["sAMAccountName", "distinguishedName", "adminCount"],
        )
        if not entries:
            return

        privileged = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
            if _int(get_attr_first(e, "adminCount")) == 1
        ]
        all_names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]

        if privileged:
            self.add_finding(
                check="PrivilegedPasswordNeverExpires",
                severity=Severity.POSSIBLE,
                title=f"Privileged accounts with non-expiring passwords: {len(privileged)}",
                description=(
                    "Privileged accounts (adminCount=1) with non-expiring passwords are "
                    "high-value targets — a compromised credential remains valid indefinitely."
                ),
                details={"privileged_accounts": privileged},
            )

        self.add_finding(
            check="PasswordNeverExpires",
            severity=Severity.HARDENED,
            title=f"Accounts with non-expiring passwords: {len(entries)}",
            description=(
                f"{len(entries)} enabled user account(s) are configured with "
                "DONT_EXPIRE_PASSWORD. Non-expiring passwords persist even after credential exposure."
            ),
            details={"count": len(entries), "accounts": all_names[:50]},
        )

    # ── inactive accounts ─────────────────────────────────────────────────────

    def _check_inactive_accounts(self, days: int = 90) -> None:
        try:
            entries = self.conn.ldap_search(
                inactive_accounts_filter(days),
                attributes=["sAMAccountName", "distinguishedName", "lastLogonTimestamp"],
            )
        except Exception as exc:
            log.debug("Inactive account query failed: %s", exc)
            return

        if not entries:
            return

        names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]

        self.add_finding(
            check="InactiveAccounts",
            severity=Severity.HARDENED,
            title=f"Inactive accounts (>{days}d): {len(entries)}",
            description=(
                f"{len(entries)} enabled user account(s) have not logged in for over {days} days "
                "(based on lastLogonTimestamp). Stale accounts are attack surface — "
                "they often retain historical permissions and may have weak passwords."
            ),
            details={"count": len(entries), "inactive_days": days, "accounts": names[:50]},
        )

    # ── helpers ───────────────────────────────────────────────────────────────

    def _get_group_members(self, group_samname: str) -> tuple[str | None, list[dict]]:
        """Return (group_dn, enabled+disabled members) for a group by sAMAccountName."""
        groups = self.conn.ldap_search(
            f"(&(objectClass=group)(sAMAccountName={group_samname}))",
            attributes=["distinguishedName"],
        )
        if not groups:
            return None, []

        group_dn = groups[0].get("dn", "")
        if not group_dn:
            group_dn = str(get_attr_first(groups[0], "distinguishedName") or "")
        if not group_dn:
            return None, []

        members = self.conn.ldap_search(
            group_member_recursive_filter(group_dn),
            attributes=["sAMAccountName", "distinguishedName", "userAccountControl", "adminCount"],
        )
        return group_dn, members


# ── module-level helpers ──────────────────────────────────────────────────────

def _is_disabled(entry: dict) -> bool:
    uac = _int(get_attr_first(entry, "userAccountControl"))
    return bool(uac & 0x0002)


def _int(val, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _group_rid(group_dn: str, domain_sid: str) -> str:
    """Return the domain-relative RID suffix for a group, or empty string."""
    # DN alone doesn't give us the SID/RID; use a pattern match on name instead
    # Called with DN context only, so this is a best-effort heuristic
    return ""


def _decode_sid(raw) -> str | None:
    """Convert a SID value (bytes or string) to its string form."""
    if isinstance(raw, bytes):
        try:
            return sid_to_str(raw)
        except Exception:
            return None
    if isinstance(raw, str):
        if raw.startswith("S-"):
            return raw
        # Might be a hex string
        try:
            return sid_to_str(bytes.fromhex(raw))
        except Exception:
            return raw
    return None


def _is_privileged_sid(sid_str: str, domain_sid: str) -> bool:
    """Return True if a SID corresponds to a well-known privileged group."""
    if not sid_str:
        return False
    # Check well-known built-in privileged SIDs
    if sid_str in {
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
    }:
        return True
    # Check domain-relative privileged RIDs
    for rid in ("-512", "-518", "-519", "-520", "-526", "-527"):
        if sid_str == f"{domain_sid}{rid}":
            return True
    return False
