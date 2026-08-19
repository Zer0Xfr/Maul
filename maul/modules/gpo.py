"""GPO module — GPO permissions, GPO links, local group membership via Group Policy."""

from __future__ import annotations

import configparser
import io
import logging

from maul.core.ldap_client import build_sd_control, get_attr, get_attr_first
from maul.core.security_descriptor import (
    MASK_DANGEROUS,
    SecurityDescriptorParser,
    sd_bytes_from_entry,
)
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.ldap_filters import GPO_CONTAINERS

log = logging.getLogger(__name__)


@register
class GPOModule(ModuleBase):
    name = "gpo"
    description = "GPO permissions, links, and local group membership via Group Policy"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._sdp = SecurityDescriptorParser(self.conn)
        self._sdp.build_sid_cache()

        gpos = self._enumerate_gpos()
        if not gpos:
            self.add_finding(
                check="GPOPresent",
                severity=Severity.RECON,
                title="No Group Policy Objects found",
                description="No GPO objects returned from LDAP.",
            )
            return self.findings

        self.add_finding(
            check="GPOPresent",
            severity=Severity.RECON,
            title=f"Group Policy Objects: {len(gpos)}",
            description=f"Found {len(gpos)} GPO(s) in the domain.",
        )

        self._check_gpo_permissions(gpos)
        self._check_gpo_links(gpos)
        self._check_gptmpl_local_groups(gpos)

        return self.findings

    # ── enumeration ───────────────────────────────────────────────────────────

    def _enumerate_gpos(self) -> list[dict]:
        return self.conn.ldap_search(
            GPO_CONTAINERS,
            attributes=[
                "displayName", "name", "gPCFileSysPath",
                "distinguishedName", "nTSecurityDescriptor",
                "flags",
            ],
            controls=build_sd_control(),
        )

    def _enumerate_ou_links(self) -> list[dict]:
        """Return all OUs and the domain object that have gPLink set."""
        return self.conn.ldap_search(
            "(gPLink=*)",
            attributes=["distinguishedName", "name", "gPLink", "gPOptions"],
        )

    # ── GPO permission check ──────────────────────────────────────────────────

    def _check_gpo_permissions(self, gpos: list[dict]) -> None:
        skip = _admin_sids(self.conn)
        issues: list[dict] = []

        for gpo in gpos:
            sd_bytes = sd_bytes_from_entry(gpo)
            if sd_bytes is None:
                continue
            try:
                sd = self._sdp.parse(sd_bytes)
            except Exception:
                continue

            display = str(get_attr_first(gpo, "displayName") or get_attr_first(gpo, "name") or "?")
            dn = gpo.get("dn", "")

            for ace in sd.allow_aces():
                if ace.sid in skip or ace.is_inherited:
                    continue
                if ace.mask & MASK_DANGEROUS:
                    issues.append({
                        "gpo": display,
                        "dn":  dn,
                        "sid": ace.sid,
                        "principal": ace.principal_name,
                        "rights": _desc_mask(ace.mask),
                    })

        if not issues:
            self.add_finding(
                check="GPOPermissions",
                severity=Severity.RECON,
                title="No unexpected GPO write permissions found",
                description="All GPO DACLs appear to restrict write access to admin principals.",
            )
            return

        dc_gpos = _filter_dc_gpos(gpos, issues)
        sev = Severity.PWNED if dc_gpos else Severity.LIKELY

        self.add_finding(
            check="GPOPermissions",
            severity=sev,
            title=f"Dangerous GPO write permissions: {len(issues)} ACE(s)",
            description=(
                "Non-admin principals have write-level rights on GPO objects. "
                "Modifying a GPO that applies to Domain Controllers or privileged accounts "
                "enables arbitrary code execution on those targets."
                + (f" {len(dc_gpos)} GPO(s) linked to DCs or privileged OUs." if dc_gpos else "")
            ),
            details={
                "affected_gpos": list({i["gpo"] for i in issues}),
                "dangerous_aces": [
                    f"{i['gpo']}: {i['principal']} ({i['sid']}) — {i['rights']}"
                    for i in issues[:30]
                ],
                "dc_linked_gpos": dc_gpos,
            },
            references=["https://attack.mitre.org/techniques/T1484/001/"],
        )

    # ── GPO links ─────────────────────────────────────────────────────────────

    def _check_gpo_links(self, gpos: list[dict]) -> None:
        """Build a GPO GUID → display name map and report orphaned/interesting links."""
        gpo_map = {}
        for gpo in gpos:
            name_attr = get_attr_first(gpo, "name") or ""
            display   = get_attr_first(gpo, "displayName") or name_attr
            if name_attr:
                gpo_map[name_attr.upper()] = str(display)

        ou_entries = self._enumerate_ou_links()
        links_info: list[dict] = []

        for ou in ou_entries:
            gp_link = str(get_attr_first(ou, "gPLink") or "")
            ou_name = str(get_attr_first(ou, "name") or ou.get("dn", "?"))
            linked_guids = _parse_gplink(gp_link)
            linked_names = [gpo_map.get(g.upper(), g) for g in linked_guids]
            if linked_names:
                links_info.append({
                    "ou":     ou_name,
                    "dn":     ou.get("dn", ""),
                    "linked": linked_names,
                })

        if links_info:
            self.add_finding(
                check="GPOLinks",
                severity=Severity.RECON,
                title=f"GPO links: {len(links_info)} OU(s) with linked GPO(s)",
                description="GPO link summary across OUs and domain.",
                details={"links": [f"{l['ou']}: {', '.join(l['linked'])}" for l in links_info[:30]]},
            )

    # ── GptTmpl.inf local group membership ───────────────────────────────────

    def _check_gptmpl_local_groups(self, gpos: list[dict]) -> None:
        try:
            smb_conn = self.conn.get_smb_connection()
        except Exception as exc:
            log.debug("SMB unavailable for GptTmpl scan: %s", exc)
            return

        from maul.core.smb_client import SMBClient
        smb = SMBClient(smb_conn)

        memberships: list[dict] = []
        domain = self.conn.domain

        for gpo in gpos:
            fs_path = str(get_attr_first(gpo, "gPCFileSysPath") or "")
            display = str(get_attr_first(gpo, "displayName") or "?")
            if not fs_path:
                continue

            # fs_path is like \\domain\SYSVOL\domain\Policies\{GUID}
            # Extract relative path inside SYSVOL share
            try:
                rel = _sysvol_rel_path(fs_path, domain)
            except Exception:
                continue

            inf_path = f"{rel}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
            content = smb.read_file("SYSVOL", inf_path, silent=True)
            if not content:
                continue

            parsed = _parse_gptmpl_inf(content)
            if parsed:
                memberships.append({"gpo": display, "path": inf_path, "memberships": parsed})

        if memberships:
            self.add_finding(
                check="GPOLocalGroups",
                severity=Severity.POSSIBLE,
                title=f"Local group membership configured via GPO: {len(memberships)} GPO(s)",
                description=(
                    "Group Policy Security Templates define local group memberships on target machines. "
                    "Review these to ensure no unexpected accounts are added to local Administrators."
                ),
                details={
                    "gpos": [
                        {
                            "gpo": m["gpo"],
                            "memberships": m["memberships"],
                        }
                        for m in memberships
                    ]
                },
            )


# ── helpers ───────────────────────────────────────────────────────────────────

def _admin_sids(conn) -> frozenset[str]:
    skip = {"S-1-5-18", "S-1-5-9", "S-1-3-0"}
    try:
        dsid = conn.domain_sid
        skip.update({f"{dsid}-512", f"{dsid}-519", f"{dsid}-520",
                     "S-1-5-32-544"})
    except Exception:
        pass
    return frozenset(skip)


def _desc_mask(mask: int) -> str:
    parts = []
    if mask & 0x10000000: parts.append("GenericAll")
    if mask & 0x40000000: parts.append("GenericWrite")
    if mask & 0x00040000: parts.append("WriteDACL")
    if mask & 0x00080000: parts.append("WriteOwner")
    return ", ".join(parts) or f"0x{mask:08x}"


def _parse_gplink(gplink: str) -> list[str]:
    """Parse gPLink attribute into a list of GPO GUIDs."""
    guids = []
    for segment in gplink.split("]"):
        segment = segment.strip().lstrip("[")
        if not segment:
            continue
        # Format: LDAP://cn={GUID},... ;0 or ;1 or ;2 or ;3
        if "}" in segment:
            start = segment.rfind("{")
            end   = segment.rfind("}")
            if start != -1 and end != -1:
                guids.append(segment[start:end + 1])
    return guids


def _filter_dc_gpos(gpos: list[dict], issues: list[dict]) -> list[str]:
    """Return display names of GPOs in the issues list that are likely DC-linked."""
    # Heuristic: GPOs named "Default Domain Controllers Policy" or linked paths containing "DomainControllers"
    dc_related = set()
    for gpo in gpos:
        display = str(get_attr_first(gpo, "displayName") or "")
        if "controller" in display.lower() or "default domain policy" in display.lower():
            dc_related.add(display)
    return [i["gpo"] for i in issues if i["gpo"] in dc_related]


def _sysvol_rel_path(fs_path: str, domain: str) -> str:
    """Convert a \\server\SYSVOL\... path to the SYSVOL-relative path."""
    # \\domain\SYSVOL\domain\Policies\{GUID} → \domain\Policies\{GUID}
    normalized = fs_path.replace("/", "\\")
    # Strip the UNC prefix and share name: \\server\SYSVOL
    parts = [p for p in normalized.split("\\") if p]
    # parts[0]=server, parts[1]=SYSVOL, rest=relative
    if len(parts) < 3:
        raise ValueError(f"Unexpected fs_path format: {fs_path}")
    return "\\" + "\\".join(parts[2:])


def _parse_gptmpl_inf(content: bytes) -> list[str]:
    """Parse GptTmpl.inf and return Group Membership entries."""
    try:
        text = content.decode("utf-16-le", errors="replace")
    except Exception:
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return []

    parser = configparser.RawConfigParser()
    try:
        parser.read_string(text)
    except Exception:
        return []

    if not parser.has_section("Group Membership"):
        return []

    results = []
    for key, value in parser.items("Group Membership"):
        if "__members" in key.lower():
            group_sid = key.split("__")[0].strip()
            members   = [m.strip() for m in value.split(",") if m.strip()]
            if members:
                results.append(f"{group_sid} Members: {', '.join(members)}")
    return results
