"""Application module — Exchange, SCCM, and third-party application server detection."""

from __future__ import annotations

import logging

from maul.core.ldap_client import build_sd_control, get_attr, get_attr_first
from maul.core.security_descriptor import (
    MASK_DANGEROUS,
    SecurityDescriptorParser,
    sd_bytes_from_entry,
)
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.constants import PRIVILEGED_BUILTIN_SIDS

log = logging.getLogger(__name__)

# Exchange Windows Permissions group — well-known RID suffix
_EWP_GROUP_NAME = "Exchange Windows Permissions"
_EXCHANGE_TRUSTED_SUBSYSTEM = "Exchange Trusted Subsystem"

# SCCM / ConfigMgr AD schema attributes
_SCCM_SCHEMA_ATTRS = [
    "mSSMSCapabilities",
    "mSSMSSiteCode",
    "mSSMSDefaultMP",
]


@register
class ApplicationModule(ModuleBase):
    name = "application"
    description = "Exchange server detection, PrivExchange, SCCM/ConfigMgr enumeration"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._sdp = SecurityDescriptorParser(self.conn)
        self._sdp.build_sid_cache()

        self._check_exchange()
        self._check_sccm()
        self._check_adfs()

        return self.findings

    # ── Exchange ──────────────────────────────────────────────────────────────

    def _check_exchange(self) -> None:
        exchange_servers = self._find_exchange_servers()
        if not exchange_servers:
            self.add_finding(
                check="Exchange",
                severity=Severity.INFO,
                title="No Exchange servers detected",
                description="No Exchange enrollment service or server objects found in AD.",
            )
            return

        versions = [s.get("version", "Unknown") for s in exchange_servers]
        hostnames = [s.get("hostname", "?") for s in exchange_servers]

        self.add_finding(
            check="Exchange",
            severity=Severity.INFO,
            title=f"Exchange servers detected: {len(exchange_servers)}",
            description="Microsoft Exchange server(s) found in the domain.",
            details={
                "servers": hostnames,
                "versions": list(set(versions)),
            },
        )

        self._check_priv_exchange()

    def _find_exchange_servers(self) -> list[dict]:
        results = []

        # Method 1: msExchExchangeServer objects in Configuration NC
        entries = self.conn.ldap_search(
            "(objectClass=msExchExchangeServer)",
            attributes=["cn", "msExchProductID", "distinguishedName", "networkAddress"],
            base=self.conn.config_dn,
        )
        for e in entries:
            results.append({
                "hostname": str(get_attr_first(e, "cn") or "?"),
                "version":  str(get_attr_first(e, "msExchProductID") or "Unknown"),
                "dn":       e.get("dn", ""),
            })

        # Method 2: SPNs on computer objects (exchangeMDB/*)
        if not results:
            spn_entries = self.conn.ldap_search(
                "(servicePrincipalName=exchangeMDB/*)",
                attributes=["dNSHostName", "sAMAccountName"],
            )
            for e in spn_entries:
                results.append({
                    "hostname": str(get_attr_first(e, "dNSHostName") or get_attr_first(e, "sAMAccountName") or "?"),
                    "version":  "Unknown (SPN-based detection)",
                    "dn":       e.get("dn", ""),
                })

        return results

    def _check_priv_exchange(self) -> None:
        """Check for PrivExchange: Exchange Windows Permissions group with WriteDACL on domain."""
        # Find the Exchange Windows Permissions group
        ewp_entries = self.conn.ldap_search(
            f"(&(objectClass=group)(cn={_EWP_GROUP_NAME}))",
            attributes=["distinguishedName", "objectSid"],
        )
        if not ewp_entries:
            return

        ewp_dn  = ewp_entries[0].get("dn", "")
        ewp_sid = _extract_sid_str(ewp_entries[0])

        # Check domain root DACL for WriteDACL from EWP
        domain_entries = self.conn.ldap_search(
            "(objectClass=domain)",
            attributes=["nTSecurityDescriptor"],
            base=self.conn.root_dn,
            scope="BASE",
            controls=build_sd_control(),
        )
        if not domain_entries:
            return

        sd_bytes = sd_bytes_from_entry(domain_entries[0])
        if sd_bytes is None:
            return

        try:
            sd = self._sdp.parse(sd_bytes)
        except Exception as exc:
            log.debug("Failed to parse domain root SD: %s", exc)
            return

        ewp_has_writedac = False
        for ace in sd.allow_aces():
            if ewp_sid and ace.sid == ewp_sid:
                if ace.mask & 0x00040000:  # WriteDACL
                    ewp_has_writedac = True
                    break
            # Also check by name if SID extraction failed
            if _EWP_GROUP_NAME.lower() in (ace.principal_name or "").lower():
                if ace.mask & 0x00040000:
                    ewp_has_writedac = True
                    break

        if ewp_has_writedac:
            self.add_finding(
                check="PrivExchange",
                severity=Severity.HIGH,
                title="PrivExchange: Exchange Windows Permissions has WriteDACL on domain",
                description=(
                    "The 'Exchange Windows Permissions' group has WriteDACL on the domain object. "
                    "Any Exchange server or user with membership in this group can grant themselves "
                    "DCSync rights (DS-Replication-Get-Changes-All) and dump all domain credentials. "
                    "Combined with NTLM relay via the Exchange PushSubscription API (CVE-2019-0686), "
                    "this is a one-shot domain compromise."
                ),
                details={
                    "ewp_group_dn": ewp_dn,
                    "domain_dn":    self.conn.root_dn,
                },
                references=[
                    "https://attack.mitre.org/techniques/T1557/001/",
                    "https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/",
                ],
            )
        else:
            self.add_finding(
                check="PrivExchange",
                severity=Severity.INFO,
                title="PrivExchange: Exchange Windows Permissions does not have WriteDACL on domain",
                description=(
                    "The Exchange Windows Permissions group does not appear to have WriteDACL "
                    "on the domain root object. PrivExchange attack path not available."
                ),
            )

    # ── SCCM / ConfigMgr ─────────────────────────────────────────────────────

    def _check_sccm(self) -> None:
        sccm_found = self._find_sccm()
        if not sccm_found:
            self.add_finding(
                check="SCCM",
                severity=Severity.INFO,
                title="No SCCM/ConfigMgr deployment detected",
                description="No SCCM schema attributes or management point objects found in AD.",
            )
            return

        sites = sccm_found.get("sites", [])
        mps   = sccm_found.get("management_points", [])

        self.add_finding(
            check="SCCM",
            severity=Severity.MEDIUM,
            title=f"SCCM/ConfigMgr detected: {len(sites)} site(s), {len(mps)} management point(s)",
            description=(
                "Microsoft System Center Configuration Manager (SCCM/ConfigMgr) is deployed. "
                "SCCM can be abused for lateral movement: the SCCM server typically has local admin "
                "rights on all managed clients. The NAA (Network Access Account) credentials are "
                "retrievable from managed machines and the SCCM DB."
            ),
            details={
                "sites": sites,
                "management_points": mps,
            },
            references=[
                "https://attack.mitre.org/techniques/T1072/",
                "https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9",
            ],
        )

    def _find_sccm(self) -> dict | None:
        sites: list[str] = []
        mps:   list[str] = []

        # Check System Management container in AD
        sm_container = f"CN=System Management,CN=System,{self.conn.root_dn}"
        entries = self.conn.ldap_search(
            "(objectClass=mSSMSSite)",
            attributes=["cn", "mSSMSSiteCode", "mSSMSDefaultMP"],
            base=sm_container,
        )
        for e in entries:
            site_code = str(get_attr_first(e, "mSSMSSiteCode") or get_attr_first(e, "cn") or "?")
            mp        = str(get_attr_first(e, "mSSMSDefaultMP") or "")
            sites.append(site_code)
            if mp:
                mps.append(mp)

        # Fallback: look for SCCM server SPNs
        if not sites:
            spn_entries = self.conn.ldap_search(
                "(servicePrincipalName=SMS/SMSPXE*)",
                attributes=["dNSHostName", "sAMAccountName"],
            )
            for e in spn_entries:
                hostname = str(get_attr_first(e, "dNSHostName") or get_attr_first(e, "sAMAccountName") or "?")
                sites.append(f"SPN-detected: {hostname}")

        if not sites and not mps:
            return None

        return {"sites": sites, "management_points": mps}

    # ── AD FS ─────────────────────────────────────────────────────────────────

    def _check_adfs(self) -> None:
        """Detect AD FS deployment and check for Golden SAML risk."""
        adfs_entries = self.conn.ldap_search(
            "(objectClass=msAuthz-ResourceCondition)",
            attributes=["cn", "distinguishedName"],
            base=self.conn.config_dn,
        )

        # Primary detection: ADFS service objects in Configuration NC
        adfs_service = self.conn.ldap_search(
            "(|(objectClass=msDS-ClaimsProviderTrust)(objectClass=msDS-RelyingPartyTrust))",
            attributes=["cn", "distinguishedName"],
            base=self.conn.config_dn,
        )

        # Tertiary: SPN-based detection
        adfs_spn = self.conn.ldap_search(
            "(servicePrincipalName=adfs/*)",
            attributes=["dNSHostName", "sAMAccountName"],
        )

        if not adfs_entries and not adfs_service and not adfs_spn:
            return  # No ADFS — skip silently

        servers: list[str] = []
        for e in adfs_spn:
            h = str(get_attr_first(e, "dNSHostName") or get_attr_first(e, "sAMAccountName") or "?")
            servers.append(h)

        claims_providers = [str(get_attr_first(e, "cn") or "?") for e in adfs_service]

        self.add_finding(
            check="ADFS",
            severity=Severity.MEDIUM,
            title="AD FS deployment detected",
            description=(
                "Active Directory Federation Services (AD FS) is deployed. "
                "The AD FS DKM (Distributed Key Manager) master key stored in AD can be extracted "
                "by Domain Admins to forge SAML tokens for any relying party (Golden SAML). "
                "The AD FS service account has read access to the DKM container by default."
            ),
            details={
                "adfs_servers": servers or ["(detected via schema/trusts — no SPN found)"],
                "relying_party_trusts": claims_providers[:20],
            },
            references=[
                "https://attack.mitre.org/techniques/T1606/002/",
                "https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps",
            ],
        )


# ── helpers ───────────────────────────────────────────────────────────────────

def _extract_sid_str(entry: dict) -> str:
    """Extract objectSid as a canonical SID string from an LDAP entry."""
    from maul.utils.parsers import sid_to_str
    raw = get_attr_first(entry, "objectSid")
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return sid_to_str(raw)
        except Exception:
            return ""
    return str(raw)
