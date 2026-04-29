"""Domain module — domain info, password policy, trusts, DCs, LDAP/SMB signing."""

from __future__ import annotations

import logging

import ldap3

from maul.core.ldap_client import get_attr, get_attr_first
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.constants import (
    DOMAIN_FUNCTIONAL_LEVELS,
    TRUST_ATTRIBUTES,
    TRUST_DIRECTION,
    TRUST_TYPE,
)
from maul.utils.ldap_filters import DOMAIN_CONTROLLERS, FINE_GRAINED_PWD_POLICY, TRUSTED_DOMAINS
from maul.utils.parsers import filetime_to_days

log = logging.getLogger(__name__)


@register
class DomainModule(ModuleBase):
    name = "domain"
    description = "Domain configuration, password policy, trusts, DCs, LDAP/SMB signing"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._check_domain_info()
        self._check_password_policy()
        self._check_fine_grained_policies()
        self._check_trusts()
        self._check_ldap_signing()
        self._check_smb_signing()
        return self.findings

    # ── checks ────────────────────────────────────────────────────────────────

    def _check_domain_info(self) -> None:
        fl = self.conn.domain_functional_level
        fl_name = DOMAIN_FUNCTIONAL_LEVELS.get(fl, f"Level {fl}")

        dcs = self.conn.domain_controllers
        dc_names = [
            get_attr_first(dc, "dNSHostName") or get_attr_first(dc, "name") or dc.get("dn", "")
            for dc in dcs
        ]

        self.add_finding(
            check="DomainInfo",
            severity=Severity.INFO,
            title=f"Domain: {self.conn.domain}",
            description=f"Functional level: {fl_name}. {len(dc_names)} domain controller(s) found.",
            details={
                "domain": self.conn.domain,
                "root_dn": self.conn.root_dn,
                "functional_level": fl_name,
                "domain_sid": self.conn.domain_sid,
                "domain_controllers": dc_names,
            },
        )

        if 0 <= fl < 5:  # below Windows Server 2012
            self.add_finding(
                check="OldFunctionalLevel",
                severity=Severity.MEDIUM,
                title=f"Domain functional level is {fl_name}",
                description=(
                    f"The domain functional level ({fl_name}) is below Windows Server 2012. "
                    "Features like Protected Users, Kerberos armoring (FAST), "
                    "and compound authentication are unavailable."
                ),
            )

    def _check_password_policy(self) -> None:
        entries = self.conn.ldap_search(
            "(objectClass=domain)",
            attributes=[
                "minPwdLength", "maxPwdAge", "minPwdAge",
                "pwdHistoryLength", "lockoutThreshold", "lockoutDuration",
                "lockoutObservationWindow", "pwdProperties",
            ],
            base=self.conn.root_dn,
            scope="BASE",
        )
        if not entries:
            return

        p = entries[0]
        min_len = _int(get_attr_first(p, "minPwdLength"), 0)
        history = _int(get_attr_first(p, "pwdHistoryLength"), 0)
        lockout = _int(get_attr_first(p, "lockoutThreshold"), 0)
        pwd_props = _int(get_attr_first(p, "pwdProperties"), 0)
        complexity = bool(pwd_props & 0x1)
        reversible = bool(pwd_props & 0x10)

        max_age_raw = get_attr_first(p, "maxPwdAge")
        max_age_days: int | None = filetime_to_days(_int(max_age_raw, 0)) if max_age_raw is not None else None

        lockout_dur_raw = get_attr_first(p, "lockoutDuration")
        lockout_dur_min: int | None = None
        if lockout_dur_raw is not None:
            days = filetime_to_days(_int(lockout_dur_raw, 0))
            lockout_dur_min = (days * 1440) if days is not None else None

        self.add_finding(
            check="PasswordPolicy",
            severity=Severity.INFO,
            title="Default domain password policy",
            description="Password policy for the default domain.",
            details={
                "min_password_length": min_len,
                "password_history": history,
                "complexity_enabled": complexity,
                "reversible_encryption": reversible,
                "max_password_age_days": max_age_days if max_age_days is not None else "Never",
                "lockout_threshold": lockout if lockout else "No lockout",
                "lockout_duration_minutes": lockout_dur_min,
            },
        )

        findings = []
        if min_len < 8:
            findings.append(self.add_finding(
                check="WeakMinPasswordLength",
                severity=Severity.HIGH,
                title=f"Minimum password length is {min_len} characters",
                description="The default policy allows very short passwords, enabling fast brute-force attacks.",
                details={"min_password_length": min_len},
                references=["https://attack.mitre.org/techniques/T1110/"],
            ))

        if lockout == 0:
            self.add_finding(
                check="NoAccountLockout",
                severity=Severity.HIGH,
                title="Account lockout is not configured",
                description=(
                    "No lockout threshold is set. Attackers can perform unlimited password-guessing "
                    "attempts (spray or brute-force) without triggering a lockout."
                ),
                details={"lockout_threshold": 0},
                references=["https://attack.mitre.org/techniques/T1110/003/"],
            )

        if not complexity:
            self.add_finding(
                check="NoPasswordComplexity",
                severity=Severity.MEDIUM,
                title="Password complexity is not enforced",
                description="Passwords are not required to contain mixed character types.",
            )

        if max_age_days is None:
            self.add_finding(
                check="PasswordsNeverExpire",
                severity=Severity.LOW,
                title="Default policy: passwords never expire",
                description="No maximum password age is set — compromised credentials may go undetected indefinitely.",
            )

        if reversible:
            self.add_finding(
                check="ReversibleEncryption",
                severity=Severity.HIGH,
                title="Passwords stored with reversible encryption",
                description=(
                    "The 'Store passwords using reversible encryption' setting is enabled. "
                    "This is equivalent to storing plaintext passwords."
                ),
            )

    def _check_fine_grained_policies(self) -> None:
        from maul.utils.ldap_filters import PASSWORD_SETTINGS_CONTAINER
        pso_base = f"{PASSWORD_SETTINGS_CONTAINER},{self.conn.root_dn}"

        try:
            entries = self.conn.ldap_search(
                FINE_GRAINED_PWD_POLICY,
                attributes=[
                    "name", "msDS-PasswordSettingsPrecedence",
                    "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
                    "msDS-MaximumPasswordAge", "msDS-PasswordComplexityEnabled",
                    "msDS-PSOAppliesTo",
                ],
                base=pso_base,
            )
        except Exception:
            return  # PSC may not exist in older domains

        for pso in entries:
            name = str(get_attr_first(pso, "name") or "?")
            min_len = _int(get_attr_first(pso, "msDS-MinimumPasswordLength"), 0)
            lockout = _int(get_attr_first(pso, "msDS-LockoutThreshold"), 0)
            complexity = get_attr_first(pso, "msDS-PasswordComplexityEnabled")
            applies_to = get_attr(pso, "msDS-PSOAppliesTo") or []
            if not isinstance(applies_to, list):
                applies_to = [str(applies_to)]

            self.add_finding(
                check="FineGrainedPolicy",
                severity=Severity.INFO,
                title=f"Fine-grained password policy: {name}",
                description=f"PSO {name!r} applies to {len(applies_to)} target(s).",
                details={
                    "name": name,
                    "min_length": min_len,
                    "lockout_threshold": lockout,
                    "complexity": complexity,
                    "applies_to": applies_to,
                },
            )

            if min_len < 8 or lockout == 0:
                self.add_finding(
                    check="WeakFineGrainedPolicy",
                    severity=Severity.MEDIUM,
                    title=f"Fine-grained policy {name!r} has weak settings",
                    description=(
                        f"PSO {name!r} sets min length={min_len}, lockout={lockout}. "
                        "Weaker than recommended."
                    ),
                    details={"name": name, "min_length": min_len, "lockout_threshold": lockout},
                )

    def _check_trusts(self) -> None:
        entries = self.conn.ldap_search(
            TRUSTED_DOMAINS,
            attributes=["name", "trustDirection", "trustType", "trustAttributes", "flatName"],
            base=self.conn.root_dn,
        )

        for trust in entries:
            name = str(get_attr_first(trust, "name") or "?")
            direction_val = _int(get_attr_first(trust, "trustDirection"), 0)
            type_val = _int(get_attr_first(trust, "trustType"), 0)
            attrs_val = _int(get_attr_first(trust, "trustAttributes"), 0)

            direction = TRUST_DIRECTION.get(direction_val, str(direction_val))
            trust_type = TRUST_TYPE.get(type_val, str(type_val))
            active_attrs = [lbl for bit, lbl in TRUST_ATTRIBUTES.items() if attrs_val & bit]

            severity = Severity.INFO
            notes: list[str] = []

            is_bidirectional = direction_val == 3
            is_forest = bool(attrs_val & 0x8)   # FOREST_TRANSITIVE
            is_quarantined = bool(attrs_val & 0x4)  # QUARANTINED_DOMAIN (SID filtering)
            is_inbound = direction_val in (1, 3)

            if is_bidirectional and is_forest:
                severity = Severity.MEDIUM
                notes.append(
                    "Bidirectional forest trust — compromise of the trusted forest enables "
                    "cross-forest privilege escalation."
                )

            if is_inbound and not is_quarantined and not is_forest:
                severity = Severity.MEDIUM
                notes.append(
                    "External trust without SID filtering (quarantine) — "
                    "SID history attacks may enable cross-domain privilege escalation."
                )

            self.add_finding(
                check="DomainTrust",
                severity=severity,
                title=f"Trust: {name} ({direction})",
                description=(notes[0] if notes else f"{direction} {trust_type} trust with {name!r}."),
                details={
                    "trusted_domain": name,
                    "direction": direction,
                    "trust_type": trust_type,
                    "attributes": active_attrs,
                    "sid_filtering": is_quarantined,
                    "notes": notes,
                },
            )

    def _check_ldap_signing(self) -> None:
        """Determine whether unsigned NTLM LDAP binds are accepted."""
        # ldap3 does not negotiate signing with NTLM by default on port 389.
        # A successful NTLM bind over port 389 indicates the DC accepts unsigned binds.
        if self.conn.use_ldaps:
            self.add_finding(
                check="LDAPSEnabled",
                severity=Severity.INFO,
                title="Connection uses LDAPS (port 636)",
                description="LDAPS was used — channel encryption is in place. Verify LDAP channel binding is also enforced.",
            )
            return

        if self.conn.use_kerberos:
            # Kerberos inherently provides integrity — can't test NTLM signing separately
            return

        # We connected with NTLM on port 389 → unsigned bind was accepted
        self.add_finding(
            check="LDAPSigningNotRequired",
            severity=Severity.HIGH,
            title="LDAP signing is not required on the domain controller",
            description=(
                "The DC accepted an NTLM LDAP bind on port 389 without requiring message signing. "
                "This enables LDAP relay attacks — an attacker who intercepts NTLM authentication "
                "(e.g. via Responder) can relay it to LDAP and create accounts, modify ACLs, "
                "or add themselves to privileged groups."
            ),
            details={"dc": self.conn.dc, "port": 389},
            references=[
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-8563",
                "https://attack.mitre.org/techniques/T1557/",
            ],
        )

    def _check_smb_signing(self) -> None:
        """Check whether the DC requires SMB signing."""
        try:
            smb = self.conn.get_smb_connection()
            signing_required = smb.isSigningRequired()
        except Exception as exc:
            log.debug("SMB signing check failed: %s", exc)
            return

        if not signing_required:
            self.add_finding(
                check="SMBSigningNotRequired",
                severity=Severity.MEDIUM,
                title="SMB signing is not required on the domain controller",
                description=(
                    "The DC does not require SMB message signing. "
                    "This enables SMB relay attacks against the DC — "
                    "an attacker can relay SMB authentication to the DC and execute commands."
                ),
                details={"dc": self.conn.dc, "signing_required": False},
                references=["https://attack.mitre.org/techniques/T1557/001/"],
            )
        else:
            self.add_finding(
                check="SMBSigningRequired",
                severity=Severity.INFO,
                title="SMB signing is required on the domain controller",
                description="The DC enforces SMB signing. Direct SMB relay to this DC is not possible.",
                details={"dc": self.conn.dc, "signing_required": True},
            )


# ── helpers ───────────────────────────────────────────────────────────────────

def _int(val, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
