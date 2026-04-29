"""Delegation module — unconstrained, constrained, and RBCD enumeration."""

from __future__ import annotations

import logging

from maul.core.ldap_client import get_attr, get_attr_first
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.ldap_filters import (
    CONSTRAINED_DELEGATION,
    RBCD,
    UNCONSTRAINED_DELEGATION,
    and_,
    or_,
    uac_bit,
    uac_bit_not,
)

log = logging.getLogger(__name__)


@register
class DelegationModule(ModuleBase):
    name = "delegation"
    description = "Unconstrained, constrained, and RBCD delegation enumeration"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._check_unconstrained()
        self._check_constrained()
        self._check_rbcd()
        return self.findings

    # ── unconstrained delegation ──────────────────────────────────────────────

    def _check_unconstrained(self) -> None:
        """Find computers and users with unconstrained delegation (TRUSTED_FOR_DELEGATION)."""

        # Computers: exclude DCs (SERVER_TRUST_ACCOUNT = 0x2000)
        computers = self.conn.ldap_search(
            UNCONSTRAINED_DELEGATION,
            attributes=["sAMAccountName", "dNSHostName", "operatingSystem", "distinguishedName"],
        )

        # User accounts with unconstrained delegation (rare but critical)
        user_filter = and_("(objectClass=user)", uac_bit(0x80000), uac_bit_not(0x0002))
        users = self.conn.ldap_search(
            user_filter,
            attributes=["sAMAccountName", "distinguishedName", "adminCount"],
        )

        all_objects = [("computer", e) for e in computers] + [("user", e) for e in users]

        if not all_objects:
            self.add_finding(
                check="UnconstrainedDelegation",
                severity=Severity.INFO,
                title="No unconstrained delegation configured",
                description="No non-DC computers or user accounts have TRUSTED_FOR_DELEGATION set.",
            )
            return

        names = []
        for obj_type, entry in all_objects:
            sam = get_attr_first(entry, "sAMAccountName") or entry.get("dn", "?")
            dns = get_attr_first(entry, "dNSHostName")
            label = f"{sam} ({dns})" if dns else str(sam)
            if obj_type == "user":
                label += " [USER]"
            names.append(label)

        self.add_finding(
            check="UnconstrainedDelegation",
            severity=Severity.HIGH,
            title=f"Unconstrained delegation: {len(all_objects)} object(s)",
            description=(
                "Objects with unconstrained delegation capture a copy of any user's TGT when that "
                "user authenticates to them. Compromising these machines grants the attacker those TGTs — "
                "which can then be used for Kerberos impersonation (e.g. with 'Printer Bug' / SpoolSample)."
            ),
            details={
                "count": len(all_objects),
                "objects": names,
            },
            references=[
                "https://attack.mitre.org/techniques/T1558/",
                "https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-dc6cf8c20ae3",
            ],
        )

    # ── constrained delegation ────────────────────────────────────────────────

    def _check_constrained(self) -> None:
        """Find objects with constrained delegation (msDS-AllowedToDelegateTo)."""
        entries = self.conn.ldap_search(
            CONSTRAINED_DELEGATION,
            attributes=[
                "sAMAccountName", "distinguishedName", "userAccountControl",
                "msDS-AllowedToDelegateTo",
            ],
        )

        if not entries:
            self.add_finding(
                check="ConstrainedDelegation",
                severity=Severity.INFO,
                title="No constrained delegation configured",
                description="No objects have msDS-AllowedToDelegateTo set.",
            )
            return

        for entry in entries:
            sam = str(get_attr_first(entry, "sAMAccountName") or entry.get("dn", "?"))
            uac = _int(get_attr_first(entry, "userAccountControl"))
            allowed_to = get_attr(entry, "msDS-AllowedToDelegateTo") or []
            if not isinstance(allowed_to, list):
                allowed_to = [str(allowed_to)]

            # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 → protocol transition (any user can be impersonated)
            has_protocol_transition = bool(uac & 0x1000000)

            severity = Severity.HIGH if has_protocol_transition else Severity.MEDIUM
            proto_note = " WITH protocol transition (any user can be impersonated)" if has_protocol_transition else ""

            self.add_finding(
                check="ConstrainedDelegation",
                severity=severity,
                title=f"Constrained delegation{proto_note}: {sam}",
                description=(
                    f"{sam!r} can delegate to {len(allowed_to)} service(s){proto_note}. "
                    + (
                        "Protocol transition allows impersonating any domain user to these services "
                        "without requiring the user's credentials (S4U2Self + S4U2Proxy)."
                        if has_protocol_transition
                        else "S4U2Proxy only — the user must authenticate first."
                    )
                ),
                details={
                    "account": sam,
                    "protocol_transition": has_protocol_transition,
                    "allowed_to_delegate_to": allowed_to,
                },
                references=["https://attack.mitre.org/techniques/T1558/"],
            )

    # ── RBCD ──────────────────────────────────────────────────────────────────

    def _check_rbcd(self) -> None:
        """Find objects with Resource-Based Constrained Delegation configured."""
        entries = self.conn.ldap_search(
            RBCD,
            attributes=[
                "sAMAccountName", "distinguishedName",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )

        if not entries:
            self.add_finding(
                check="RBCD",
                severity=Severity.INFO,
                title="No RBCD configured",
                description="No objects have msDS-AllowedToActOnBehalfOfOtherIdentity set.",
            )
            return

        names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]

        self.add_finding(
            check="RBCD",
            severity=Severity.MEDIUM,
            title=f"Resource-Based Constrained Delegation: {len(entries)} object(s)",
            description=(
                f"{len(entries)} object(s) have msDS-AllowedToActOnBehalfOfOtherIdentity set. "
                "RBCD allows the accounts listed in that attribute's security descriptor to impersonate "
                "any user to the target service via S4U2Self + S4U2Proxy. "
                "Full ACL analysis required to identify who is listed (Phase 3)."
            ),
            details={
                "count": len(entries),
                "targets": names,
            },
            references=[
                "https://attack.mitre.org/techniques/T1558/",
                "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html",
            ],
        )


def _int(val, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
