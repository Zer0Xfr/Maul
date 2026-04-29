"""Rights module — DCSync, dangerous ACLs on sensitive AD objects."""

from __future__ import annotations

import logging

from maul.core.ldap_client import build_sd_control, get_attr_first
from maul.core.security_descriptor import (
    MASK_CREATE_CHILD,
    MASK_DANGEROUS,
    MASK_EXTENDED_RIGHT,
    MASK_GENERIC_ALL,
    MASK_WRITE_DAC,
    MASK_WRITE_OWNER,
    ParsedACE,
    ParsedSD,
    SecurityDescriptorParser,
    sd_bytes_from_entry,
)
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.constants import EXTENDED_RIGHTS, PRIVILEGED_BUILTIN_SIDS

log = logging.getLogger(__name__)

# DCSync-required extended right GUIDs
_GUID_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
_GUID_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"

# Password reset right
_GUID_FORCE_CHANGE_PASS = "00299570-246d-11d0-a768-00aa006e0529"

# ACL-checked objects
_SENSITIVE_OBJECTS = [
    ("CN=AdminSDHolder,CN=System,{root_dn}", "AdminSDHolder", "Its DACL is propagated to all protected groups every 60 min"),
    ("{root_dn}",                            "Domain root",   "Controls DCSync rights and domain-wide permissions"),
]


@register
class RightsModule(ModuleBase):
    name = "rights"
    description = "DCSync rights, dangerous ACLs on sensitive AD objects, password reset rights"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._sdp = SecurityDescriptorParser(self.conn)
        self._sdp.build_sid_cache()
        self._check_dcsync()
        self._check_sensitive_object_acls()
        self._check_ou_acls()
        return self.findings

    # ── DCSync ────────────────────────────────────────────────────────────────

    def _check_dcsync(self) -> None:
        entries = self.conn.ldap_search(
            "(objectClass=domain)",
            attributes=["nTSecurityDescriptor"],
            base=self.conn.root_dn,
            scope="BASE",
            controls=build_sd_control(),
        )
        if not entries:
            return

        sd_bytes = sd_bytes_from_entry(entries[0])
        if sd_bytes is None:
            log.debug("nTSecurityDescriptor not returned for domain root")
            return

        sd = self._sdp.parse(sd_bytes)

        # Group ACEs by SID — collect which replication rights each SID has
        sid_rights: dict[str, set[str]] = {}
        for ace in sd.allow_aces():
            if ace.is_inherited:
                continue
            sid = ace.sid
            # GenericAll = implicit DCSync
            if ace.mask & MASK_GENERIC_ALL:
                sid_rights.setdefault(sid, set()).update(
                    {_GUID_GET_CHANGES, _GUID_GET_CHANGES_ALL}
                )
            # All extended rights (EXTENDED_RIGHT with no ObjectType)
            if (ace.mask & MASK_EXTENDED_RIGHT) and not ace.object_type_guid:
                sid_rights.setdefault(sid, set()).update(
                    {_GUID_GET_CHANGES, _GUID_GET_CHANGES_ALL}
                )
            # Specific replication GUIDs
            for guid in (_GUID_GET_CHANGES, _GUID_GET_CHANGES_ALL, _GUID_GET_CHANGES_FILTERED):
                if ace.grants_extended_right(guid):
                    sid_rights.setdefault(sid, set()).add(guid)

        # DCs and the system account legitimately have these rights
        skip_sids = _dc_sids(self.conn)

        dcsync_capable: list[dict] = []
        for sid, rights in sid_rights.items():
            if sid in skip_sids:
                continue
            has_both = (
                _GUID_GET_CHANGES in rights
                and _GUID_GET_CHANGES_ALL in rights
            )
            if has_both:
                dcsync_capable.append({
                    "sid": sid,
                    "name": self._sdp.resolve_sid(sid),
                    "rights": [EXTENDED_RIGHTS.get(g, g) for g in sorted(rights)],
                })

        if not dcsync_capable:
            self.add_finding(
                check="DCSync",
                severity=Severity.INFO,
                title="No non-DC DCSync rights found",
                description="No unexpected principals have DS-Replication-Get-Changes-All on the domain object.",
            )
            return

        self.add_finding(
            check="DCSync",
            severity=Severity.CRITICAL,
            title=f"DCSync rights: {len(dcsync_capable)} non-DC principal(s)",
            description=(
                "The following principals have both DS-Replication-Get-Changes and "
                "DS-Replication-Get-Changes-All on the domain object. "
                "This allows them to replicate all secrets (including krbtgt and all user NTHashes) "
                "using DCSync (mimikatz lsadump::dcsync) without touching any DC disk or log."
            ),
            details={
                "principals": [
                    f"{e['name']} ({e['sid']}): {', '.join(e['rights'])}"
                    for e in dcsync_capable
                ]
            },
            references=[
                "https://attack.mitre.org/techniques/T1003/006/",
                "https://adsecurity.org/?p=1729",
            ],
        )

    # ── sensitive object ACLs ─────────────────────────────────────────────────

    def _check_sensitive_object_acls(self) -> None:
        for dn_template, label, context in _SENSITIVE_OBJECTS:
            dn = dn_template.format(root_dn=self.conn.root_dn)
            self._check_object_acl(dn, label, context)

    def _check_object_acl(self, dn: str, label: str, context: str) -> None:
        entries = self.conn.ldap_search(
            "(objectClass=*)",
            attributes=["nTSecurityDescriptor"],
            base=dn,
            scope="BASE",
            controls=build_sd_control(),
        )
        if not entries:
            log.debug("Object not found: %s", dn)
            return

        sd_bytes = sd_bytes_from_entry(entries[0])
        if sd_bytes is None:
            return

        sd = self._sdp.parse(sd_bytes)
        skip_sids = _dc_sids(self.conn)

        dangerous: list[dict] = []
        for ace in sd.allow_aces():
            if ace.sid in skip_sids:
                continue
            if not (ace.mask & MASK_DANGEROUS):
                continue
            # Inherited-only isn't directly exploitable here (but note it)
            rights = _describe_mask(ace.mask)
            dangerous.append({
                "sid":       ace.sid,
                "name":      ace.principal_name,
                "rights":    rights,
                "inherited": ace.is_inherited,
            })

        if not dangerous:
            self.add_finding(
                check=f"ACL_{label.replace(' ', '')}",
                severity=Severity.INFO,
                title=f"{label}: no unexpected dangerous ACEs",
                description=f"The DACL on {label} ({dn}) contains no unexpected write-level ACEs.",
            )
            return

        explicit = [d for d in dangerous if not d["inherited"]]
        sev = Severity.CRITICAL if explicit else Severity.HIGH

        self.add_finding(
            check=f"ACL_{label.replace(' ', '')}",
            severity=sev,
            title=f"Dangerous ACL on {label}: {len(dangerous)} ACE(s)",
            description=(
                f"{context}. "
                f"{len(explicit)} explicit and {len(dangerous) - len(explicit)} inherited "
                "dangerous ACE(s) found on this object."
            ),
            details={
                "object_dn": dn,
                "dangerous_aces": [
                    f"{'[INHERITED] ' if d['inherited'] else ''}{d['name']} ({d['sid']}): {', '.join(d['rights'])}"
                    for d in dangerous
                ],
            },
            references=["https://attack.mitre.org/techniques/T1222/001/"],
        )

    # ── OU ACLs ───────────────────────────────────────────────────────────────

    def _check_ou_acls(self) -> None:
        """Check for dangerous ACEs on Organizational Units."""
        entries = self.conn.ldap_search(
            "(objectClass=organizationalUnit)",
            attributes=["nTSecurityDescriptor", "name", "distinguishedName"],
            controls=build_sd_control(),
        )

        skip_sids = _dc_sids(self.conn)
        ou_issues: list[dict] = []

        for entry in entries:
            sd_bytes = sd_bytes_from_entry(entry)
            if sd_bytes is None:
                continue
            try:
                sd = self._sdp.parse(sd_bytes)
            except Exception:
                continue

            for ace in sd.allow_aces():
                if ace.is_inherited or ace.sid in skip_sids:
                    continue
                if ace.mask & MASK_DANGEROUS:
                    ou_issues.append({
                        "ou":     entry.get("dn", "?"),
                        "name":   get_attr_first(entry, "name") or "?",
                        "sid":    ace.sid,
                        "principal": ace.principal_name,
                        "rights": _describe_mask(ace.mask),
                    })

        if not ou_issues:
            self.add_finding(
                check="OUPermissions",
                severity=Severity.INFO,
                title="No unexpected dangerous OU permissions",
                description="No explicit dangerous ACEs found on Organizational Units.",
            )
            return

        self.add_finding(
            check="OUPermissions",
            severity=Severity.HIGH,
            title=f"Dangerous OU permissions: {len(ou_issues)} ACE(s)",
            description=(
                "Non-default principals have write-level rights on Organizational Units. "
                "This can allow attackers to create/modify computer objects, link malicious GPOs, "
                "or set attributes like msDS-AllowedToActOnBehalfOfOtherIdentity."
            ),
            details={
                "affected_ous": list({i["ou"] for i in ou_issues}),
                "dangerous_aces": [
                    f"{i['ou']}: {i['principal']} ({i['sid']}) — {', '.join(i['rights'])}"
                    for i in ou_issues[:30]
                ],
            },
        )


# ── helpers ───────────────────────────────────────────────────────────────────

def _dc_sids(conn) -> frozenset[str]:
    """Return SIDs that legitimately hold DC-level rights (skip from dangerous ACL checks)."""
    skip = {
        "S-1-5-18",   # SYSTEM
        "S-1-5-9",    # Enterprise Domain Controllers
        "S-1-3-0",    # Creator Owner
    }
    try:
        dsid = conn.domain_sid
        skip.update({
            f"{dsid}-516",  # Domain Controllers
            f"{dsid}-512",  # Domain Admins
            f"{dsid}-519",  # Enterprise Admins
            f"{dsid}-518",  # Schema Admins
        })
        skip.update(PRIVILEGED_BUILTIN_SIDS)
    except Exception:
        pass
    return frozenset(skip)


def _describe_mask(mask: int) -> list[str]:
    rights = []
    if mask & MASK_GENERIC_ALL:   rights.append("GenericAll")
    if mask & 0x40000000:         rights.append("GenericWrite")
    if mask & MASK_WRITE_DAC:     rights.append("WriteDACL")
    if mask & MASK_WRITE_OWNER:   rights.append("WriteOwner")
    if mask & MASK_CREATE_CHILD:  rights.append("CreateChild")
    if mask & MASK_EXTENDED_RIGHT: rights.append("ExtendedRight")
    if mask & 0x00000020:         rights.append("WriteProperty")
    if not rights:
        rights.append(f"0x{mask:08x}")
    return rights
