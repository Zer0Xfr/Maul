"""ADCS module — CA enumeration, certificate template vulnerability checks (ESC1-ESC16)."""

from __future__ import annotations

import logging
from urllib.request import urlopen
from urllib.error import URLError

from maul.core.ldap_client import build_sd_control, get_attr, get_attr_first
from maul.core.security_descriptor import (
    MASK_DANGEROUS,
    MASK_EXTENDED_RIGHT,
    MASK_GENERIC_ALL,
    MASK_GENERIC_WRITE,
    MASK_WRITE_PROPERTY,
    SecurityDescriptorParser,
    sd_bytes_from_entry,
)
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.constants import EKU_OIDS
from maul.utils.ldap_filters import CA_ENROLLMENT_SERVICES, CERTIFICATE_TEMPLATES

log = logging.getLogger(__name__)

# Extended right GUIDs for certificate enrollment
_GUID_ENROLL       = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
_GUID_AUTOENROLL   = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# EKUs enabling domain authentication
_AUTH_EKUS: frozenset[str] = frozenset({
    "1.3.6.1.5.5.7.3.2",       # Client Authentication
    "1.3.6.1.5.2.3.4",         # PKINIT Client Auth
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "2.5.29.37.0",              # Any Purpose
})

# EKUs that by themselves make a template dangerous (ESC2)
_ANY_PURPOSE_EKU = "2.5.29.37.0"

# Certificate Request Agent EKU (ESC3)
_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

# msPKI-Certificate-Name-Flag bits
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT          = 0x00000001
_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00000002

# msPKI-Enrollment-Flag bits
_CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000  # ESC9/ESC10
_CT_FLAG_PEND_ALL_REQUESTS     = 0x00000002  # manager approval required (ESC15)

# CA flag for EDITF_ATTRIBUTESUBJECTALTNAME2
_EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000

# ESC11: CA must enforce encryption on ICertPassage RPC interface
_IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200

# ESC13: OID container
_OID_CONTAINER_CN = "CN=OID,CN=Public Key Services,CN=Services"

# ESC14: attribute schema GUIDs for sensitive write targets
_GUID_ALT_SECURITY_IDENTITIES  = "bf9679c4-0de6-11d0-a285-00aa003049e2"
_GUID_MSDS_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

# ESC15: template schema version 1 lacks application-policy enforcement
_TEMPLATE_SCHEMA_V1 = 1


@register
class ADCSModule(ModuleBase):
    name = "adcs"
    description = "AD CS CA enumeration and ESC1-ESC16 certificate template vulnerability checks"
    opsec_safe = True

    def run(self) -> list[Finding]:
        self._sdp = SecurityDescriptorParser(self.conn)
        self._sdp.build_sid_cache()

        cas = self._enumerate_cas()
        if not cas:
            self.add_finding(
                check="ADCSPresent",
                severity=Severity.INFO,
                title="No Active Directory Certificate Services found",
                description="No pKIEnrollmentService objects found in the Configuration NC.",
            )
            return self.findings

        self.add_finding(
            check="ADCSPresent",
            severity=Severity.INFO,
            title=f"Active Directory Certificate Services: {len(cas)} CA(s)",
            description=f"Found {len(cas)} CA(s): {', '.join(c['name'] for c in cas)}",
            details={"cas": [c["name"] for c in cas]},
        )

        templates = self._enumerate_templates()

        # Pre-fetch OID → group link map for ESC13
        oid_link_map = self._enumerate_oid_group_links()

        for ca in cas:
            self._check_esc6(ca)
            self._check_esc7(ca)
            self._check_esc8(ca)
            self._check_esc11(ca)
            self._check_esc12(ca)
            self._check_esc16(ca)

        for tmpl in templates:
            self._check_template(tmpl, cas, oid_link_map)

        # ESC14: scan privileged user DACLs for dangerous attribute write rights
        self._check_esc14()

        return self.findings

    # ── enumeration ───────────────────────────────────────────────────────────

    def _enumerate_cas(self) -> list[dict]:
        entries = self.conn.ldap_search(
            CA_ENROLLMENT_SERVICES,
            attributes=[
                "name", "dNSHostName", "cACertificate",
                "certificateTemplates", "msPKI-Cert-Template-OID",
                "flags", "nTSecurityDescriptor",
            ],
            base=f"CN=Public Key Services,CN=Services,{self.conn.config_dn}",
            controls=build_sd_control(),
        )
        result = []
        for e in entries:
            result.append({
                "dn":        e.get("dn", ""),
                "name":      str(get_attr_first(e, "name") or "?"),
                "dns_host":  str(get_attr_first(e, "dNSHostName") or ""),
                "templates": _as_list(get_attr(e, "certificateTemplates")),
                "flags":     _int(get_attr_first(e, "flags")),
                "sd_bytes":  sd_bytes_from_entry(e),
            })
        return result

    def _enumerate_templates(self) -> list[dict]:
        return self.conn.ldap_search(
            CERTIFICATE_TEMPLATES,
            attributes=[
                "name", "displayName", "distinguishedName",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-RA-Signature",
                "msPKI-Template-Schema-Version",
                "msPKI-Certificate-Policy",
                "pKIExtendedKeyUsage",
                "msPKI-Certificate-Application-Policy",
                "nTSecurityDescriptor",
            ],
            base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.conn.config_dn}",
            controls=build_sd_control(),
        )

    def _enumerate_oid_group_links(self) -> dict[str, str]:
        """Return {oid_value: group_dn} for all OID objects with msDS-OIDToGroupLink."""
        try:
            entries = self.conn.ldap_search(
                "(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))",
                attributes=["msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"],
                base=f"{_OID_CONTAINER_CN},{self.conn.config_dn}",
            )
        except Exception as exc:
            log.debug("OID group link enumeration failed: %s", exc)
            return {}

        result: dict[str, str] = {}
        for e in entries:
            oid = str(get_attr_first(e, "msPKI-Cert-Template-OID") or "")
            grp = str(get_attr_first(e, "msDS-OIDToGroupLink") or "")
            if oid and grp:
                result[oid] = grp
        return result

    # ── per-template checks ───────────────────────────────────────────────────

    def _check_template(self, tmpl: dict, cas: list[dict], oid_link_map: dict[str, str]) -> None:
        name = str(get_attr_first(tmpl, "name") or "?")
        dn   = tmpl.get("dn", "")

        name_flag     = _int(get_attr_first(tmpl, "msPKI-Certificate-Name-Flag"))
        enroll_flag   = _int(get_attr_first(tmpl, "msPKI-Enrollment-Flag"))
        ra_sigs       = _int(get_attr_first(tmpl, "msPKI-RA-Signature"))
        schema_ver    = _int(get_attr_first(tmpl, "msPKI-Template-Schema-Version"))
        ekus          = _as_list(get_attr(tmpl, "pKIExtendedKeyUsage"))
        app_policy    = _as_list(get_attr(tmpl, "msPKI-Certificate-Application-Policy"))
        cert_policies = _as_list(get_attr(tmpl, "msPKI-Certificate-Policy"))
        all_ekus      = set(str(e) for e in ekus + app_policy)

        enrollable_by_low_priv = self._can_low_priv_enroll(tmpl)

        supplies_subject = bool(name_flag & _CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        has_auth_eku     = bool(all_ekus & _AUTH_EKUS) or (not all_ekus)
        no_sec_ext       = bool(enroll_flag & _CT_FLAG_NO_SECURITY_EXTENSION)

        # ── ESC1 ──────────────────────────────────────────────────────────────
        if supplies_subject and has_auth_eku and enrollable_by_low_priv:
            self.add_finding(
                check="ESC1",
                severity=Severity.CRITICAL,
                title=f"ESC1: Enrollee-supplies-subject with auth EKU — {name}",
                description=(
                    f"Template {name!r} allows the enrollee to specify a Subject Alternative Name (SAN) "
                    "AND has an authentication EKU AND is enrollable by low-priv users. "
                    "An attacker can request a certificate as any domain user (including Domain Admin) "
                    "and use it for Kerberos authentication (PKINIT or LDAPS)."
                ),
                details={
                    "template": name,
                    "dn": dn,
                    "ekus": list(all_ekus),
                    "enrollee_supplies_subject": True,
                },
                references=[
                    "https://attack.mitre.org/techniques/T1649/",
                    "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                ],
            )

        # ── ESC2 ──────────────────────────────────────────────────────────────
        is_any_purpose = _ANY_PURPOSE_EKU in all_ekus or not all_ekus
        if is_any_purpose and enrollable_by_low_priv and not supplies_subject:
            self.add_finding(
                check="ESC2",
                severity=Severity.HIGH,
                title=f"ESC2: Any-purpose / no-EKU template — {name}",
                description=(
                    f"Template {name!r} has 'Any Purpose' EKU or no EKUs (SubCA behavior) "
                    "and is enrollable by low-priv users. "
                    "Certificates issued by this template can be used for any purpose, "
                    "including as an enrollment agent to obtain certificates for other users (chained with ESC3)."
                ),
                details={"template": name, "dn": dn, "ekus": list(all_ekus)},
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
            )

        # ── ESC3 ──────────────────────────────────────────────────────────────
        if _CERT_REQUEST_AGENT in all_ekus and enrollable_by_low_priv and ra_sigs == 0:
            self.add_finding(
                check="ESC3",
                severity=Severity.HIGH,
                title=f"ESC3: Certificate Request Agent template — {name}",
                description=(
                    f"Template {name!r} issues Certificate Request Agent certificates "
                    "(EKU: 1.3.6.1.4.1.311.20.2.1) with 0 RA signatures required "
                    "and is enrollable by low-priv users. "
                    "An attacker can obtain an enrollment agent cert and use it to "
                    "enroll on behalf of any user via another template."
                ),
                details={"template": name, "dn": dn, "ra_signatures": ra_sigs},
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
            )

        # ── ESC4 ──────────────────────────────────────────────────────────────
        self._check_esc4(tmpl, name, dn)

        # ── ESC9 ──────────────────────────────────────────────────────────────
        if no_sec_ext and has_auth_eku and enrollable_by_low_priv and not supplies_subject:
            self.add_finding(
                check="ESC9",
                severity=Severity.HIGH,
                title=f"ESC9: No security extension on template — {name}",
                description=(
                    f"Template {name!r} has CT_FLAG_NO_SECURITY_EXTENSION set "
                    "(msPKI-Enrollment-Flag bit 0x80000). Certificates issued from this template "
                    "will NOT contain the szOID_NTDS_CA_SECURITY_EXT SID extension "
                    "(OID 1.3.6.1.4.1.311.25.2), causing the KDC to fall back to UPN-based "
                    "certificate mapping. An attacker with GenericWrite on a target user can "
                    "change the victim's UPN to match the SAN on an attacker-controlled certificate, "
                    "obtain a cert from this template, revert the UPN, then authenticate as the victim."
                ),
                details={
                    "template": name,
                    "dn": dn,
                    "ekus": list(all_ekus),
                    "no_security_extension": True,
                },
                references=[
                    "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7",
                ],
            )

        # ── ESC10 ─────────────────────────────────────────────────────────────
        if no_sec_ext and has_auth_eku and enrollable_by_low_priv and not supplies_subject:
            self.add_finding(
                check="ESC10",
                severity=Severity.HIGH,
                title=f"ESC10: Weak certificate mapping exploitable — {name}",
                description=(
                    f"Template {name!r} has CT_FLAG_NO_SECURITY_EXTENSION set and issues auth "
                    "certificates to low-priv users. If the domain controller has "
                    "StrongCertificateBindingEnforcement set to 0 or 1 (compatibility mode), "
                    "an attacker with GenericWrite on a target user account can: "
                    "(1) change the target's UPN to match the attacker's certificate SAN, "
                    "(2) request a certificate from this template, "
                    "(3) revert the UPN change, "
                    "(4) authenticate as the victim using the certificate. "
                    "Verify DC registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\"
                    "StrongCertificateBindingEnforcement"
                ),
                details={
                    "template": name,
                    "dn": dn,
                    "ekus": list(all_ekus),
                    "no_security_extension": True,
                    "note": "Exploitation requires StrongCertificateBindingEnforcement != 2 on DC",
                },
                references=[
                    "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7",
                ],
            )

        # ── ESC13 ─────────────────────────────────────────────────────────────
        self._check_esc13(tmpl, name, dn, cert_policies, oid_link_map, enrollable_by_low_priv)

        # ── ESC15 ─────────────────────────────────────────────────────────────
        manager_approval = bool(enroll_flag & _CT_FLAG_PEND_ALL_REQUESTS)
        if (schema_ver == _TEMPLATE_SCHEMA_V1
                and enrollable_by_low_priv
                and not manager_approval
                and ra_sigs == 0):
            self.add_finding(
                check="ESC15",
                severity=Severity.HIGH,
                title=f"ESC15: Schema Version 1 template enrollable by low-priv users — {name}",
                description=(
                    f"Template {name!r} uses Schema Version 1 (msPKI-Template-Schema-Version=1), "
                    "which does not enforce Application Policy restrictions in certificate requests. "
                    "A low-priv user can enroll and specify arbitrary Application Policies "
                    "(including Client Authentication) in their request, regardless of the template's "
                    "configured EKUs. This is exploitable via CVE-2024-49019. "
                    "No manager approval and no RA signatures required."
                ),
                details={
                    "template": name,
                    "dn": dn,
                    "schema_version": schema_ver,
                    "template_ekus": list(all_ekus),
                    "manager_approval": False,
                    "ra_signatures": ra_sigs,
                },
                references=[
                    "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                    "https://www.akamai.com/blog/security-research/2024-windows-vulnerability-certifried-2",
                ],
            )

    # ── ESC4: write rights on template object ────────────────────────────────

    def _check_esc4(self, tmpl: dict, name: str, dn: str) -> None:
        sd_bytes = sd_bytes_from_entry(tmpl)
        if sd_bytes is None:
            return
        try:
            sd = self._sdp.parse(sd_bytes)
        except Exception:
            return

        skip = _admin_sids(self.conn)
        dangerous_aces = []
        for ace in sd.allow_aces():
            if ace.sid in skip or ace.is_inherited:
                continue
            if ace.mask & MASK_DANGEROUS:
                dangerous_aces.append(ace)

        if not dangerous_aces:
            return

        self.add_finding(
            check="ESC4",
            severity=Severity.HIGH,
            title=f"ESC4: Write rights on certificate template — {name}",
            description=(
                f"Non-admin principals have write-level rights on template {name!r}. "
                "This allows modifying the template flags (e.g. adding ENROLLEE_SUPPLIES_SUBJECT "
                "or a client-auth EKU) to create an ESC1 condition."
            ),
            details={
                "template": name,
                "dn": dn,
                "dangerous_aces": [
                    f"{a.principal_name} ({a.sid}): {_desc_mask(a.mask)}"
                    for a in dangerous_aces
                ],
            },
            references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        )

    # ── ESC5: write rights on CA object (covered by ESC7) ────────────────────

    def _check_esc7(self, ca: dict) -> None:
        """ESC7: ManageCA / ManageCertificates on the CA enrollment service object."""
        sd_bytes = ca.get("sd_bytes")
        if sd_bytes is None:
            return
        try:
            sd = self._sdp.parse(sd_bytes)
        except Exception:
            return

        skip = _admin_sids(self.conn)
        manage_aces = []
        for ace in sd.allow_aces():
            if ace.sid in skip or ace.is_inherited:
                continue
            if ace.mask & (MASK_GENERIC_ALL | MASK_DANGEROUS):
                manage_aces.append(ace)

        if not manage_aces:
            return

        self.add_finding(
            check="ESC7",
            severity=Severity.HIGH,
            title=f"ESC7: Dangerous rights on CA object — {ca['name']}",
            description=(
                f"Non-admin principals have write-level rights on CA {ca['name']!r}. "
                "ManageCA rights allow enabling EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) "
                "or approving pending certificate requests. ManageCertificates allows "
                "issuing failed/pending requests."
            ),
            details={
                "ca": ca["name"],
                "dn": ca["dn"],
                "dangerous_aces": [
                    f"{a.principal_name} ({a.sid}): {_desc_mask(a.mask)}"
                    for a in manage_aces
                ],
            },
            references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        )

    def _check_esc6(self, ca: dict) -> None:
        """ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA — requires RPC check, noted as manual."""
        self.add_finding(
            check="ESC6",
            severity=Severity.INFO,
            title=f"ESC6: Manual verification required for CA {ca['name']}",
            description=(
                f"CA {ca['name']!r} should be checked for EDITF_ATTRIBUTESUBJECTALTNAME2. "
                "If set, any certificate request can include a user-specified SAN, enabling "
                "ESC1-equivalent attacks even on templates without ENROLLEE_SUPPLIES_SUBJECT. "
                "This flag requires RPC/certutil access to verify remotely."
            ),
            details={"ca": ca["name"], "ca_host": ca["dns_host"]},
            references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        )

    def _check_esc8(self, ca: dict) -> None:
        """ESC8: Web enrollment endpoint (NTLM relay to ADCS HTTP)."""
        host = ca.get("dns_host", "")
        if not host:
            return

        for path in ("/certsrv/", "/certsrv/certrqus.asp"):
            url = f"http://{host}{path}"
            try:
                resp = urlopen(url, timeout=5)
                status = resp.status
            except URLError as e:
                if "refused" in str(e).lower() or "timed out" in str(e).lower():
                    continue
                if hasattr(e, "code") and e.code == 401:
                    status = 401
                else:
                    continue
            except Exception:
                continue

            self.add_finding(
                check="ESC8",
                severity=Severity.HIGH,
                title=f"ESC8: HTTP enrollment endpoint active — {ca['name']}",
                description=(
                    f"The CA web enrollment service is accessible at {url} (HTTP {status}). "
                    "An attacker who can coerce NTLM authentication from a machine account "
                    "(e.g. PetitPotam, PrinterBug) can relay it to this endpoint and "
                    "obtain a certificate for the victim machine — enabling PKINIT and "
                    "domain privilege escalation."
                ),
                details={"url": url, "http_status": status},
                references=[
                    "https://attack.mitre.org/techniques/T1649/",
                    "https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/",
                ],
            )
            break

    # ── ESC11: CA does not enforce RPC encryption ─────────────────────────────

    def _check_esc11(self, ca: dict) -> None:
        """ESC11: IF_ENFORCEENCRYPTICERTREQUEST not set — NTLM relay to RPC enrollment."""
        ca_flags = ca.get("flags", 0)
        if ca_flags & _IF_ENFORCEENCRYPTICERTREQUEST:
            return  # encryption enforced — not vulnerable

        self.add_finding(
            check="ESC11",
            severity=Severity.HIGH,
            title=f"ESC11: CA does not enforce encrypted RPC enrollment — {ca['name']}",
            description=(
                f"CA {ca['name']!r} does not have IF_ENFORCEENCRYPTICERTREQUEST (0x200) set "
                "in its flags. The ICertPassage Remote (ICPR) RPC interface accepts unencrypted "
                "enrollment requests. An attacker can relay NTLM authentication to the CA's RPC "
                "enrollment endpoint — similar to ESC8 but targeting RPC (port 135/dynamic) "
                "instead of HTTP. Coerce authentication via PrinterBug, PetitPotam, etc., then "
                "relay to ICPR to obtain a certificate for the coerced machine account."
            ),
            details={
                "ca": ca["name"],
                "ca_host": ca["dns_host"],
                "ca_flags": hex(ca_flags),
                "missing_flag": "IF_ENFORCEENCRYPTICERTREQUEST (0x200)",
            },
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/",
            ],
        )

    # ── ESC12: YubiHSM default credentials (cannot detect via LDAP) ──────────

    def _check_esc12(self, ca: dict) -> None:
        """ESC12: YubiHSM2 with default auth key — requires local CA access, not detectable via LDAP."""
        # Cannot determine HSM provider or key storage configuration from AD LDAP attributes.
        # ESC12 requires shell access to the CA server to verify YubiHSM usage and
        # whether the default authentication key (0x0001 / password "password") is unchanged.
        # No finding emitted here — flag for manual review if CA server access is obtained.
        pass

    # ── ESC13: issuance policy with OID group link ────────────────────────────

    def _check_esc13(
        self,
        tmpl: dict,
        name: str,
        dn: str,
        cert_policies: list[str],
        oid_link_map: dict[str, str],
        enrollable_by_low_priv: bool,
    ) -> None:
        """ESC13: Template issuance policy linked to a privileged AD group."""
        if not cert_policies or not oid_link_map or not enrollable_by_low_priv:
            return

        linked_groups: list[tuple[str, str]] = []
        for policy_oid in cert_policies:
            oid_str = str(policy_oid)
            group_dn = oid_link_map.get(oid_str)
            if group_dn:
                linked_groups.append((oid_str, group_dn))

        if not linked_groups:
            return

        # Check if any linked group is privileged
        privileged_groups = [
            (oid, grp) for oid, grp in linked_groups
            if _is_privileged_group_dn(grp, self.conn)
        ]

        sev = Severity.CRITICAL if privileged_groups else Severity.HIGH
        title_suffix = "privileged group" if privileged_groups else "AD group"

        self.add_finding(
            check="ESC13",
            severity=sev,
            title=f"ESC13: Issuance policy links to {title_suffix} — {name}",
            description=(
                f"Template {name!r} has an issuance policy (msPKI-Certificate-Policy) "
                "linked to an AD security group via msDS-OIDToGroupLink. "
                "When a user authenticates with a certificate issued from this template, "
                "they gain the permissions of the linked group (Authentication Mechanism Assurance). "
                "If the linked group is privileged, any user who can enroll in this template "
                "effectively gains those group's privileges upon certificate authentication."
            ),
            details={
                "template": name,
                "dn": dn,
                "linked_groups": [
                    f"{oid} → {grp}" for oid, grp in linked_groups
                ],
                "privileged_links": [
                    f"{oid} → {grp}" for oid, grp in privileged_groups
                ],
            },
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tls-improvements-to-ad-ds-and-ad-lds",
            ],
        )

    # ── ESC14: WriteProperty on altSecurityIdentities / msDS-KeyCredentialLink ─

    def _check_esc14(self) -> None:
        """ESC14: Non-admin write access to altSecurityIdentities or msDS-KeyCredentialLink."""
        try:
            entries = self.conn.ldap_search(
                "(&(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["sAMAccountName", "nTSecurityDescriptor"],
                controls=build_sd_control(),
            )
        except Exception as exc:
            log.debug("ESC14 user query failed: %s", exc)
            return

        if not entries:
            return

        skip = _admin_sids(self.conn)
        dangerous: list[str] = []

        for entry in entries:
            sam = str(get_attr_first(entry, "sAMAccountName") or "?")
            sd_bytes = sd_bytes_from_entry(entry)
            if sd_bytes is None:
                continue
            try:
                sd = self._sdp.parse(sd_bytes)
            except Exception:
                continue

            for ace in sd.allow_aces():
                if ace.sid in skip or ace.is_inherited:
                    continue

                grants_altsec = ace.grants_write_property(_GUID_ALT_SECURITY_IDENTITIES)
                grants_keycred = ace.grants_write_property(_GUID_MSDS_KEY_CREDENTIAL_LINK)
                grants_gw = bool(ace.mask & MASK_GENERIC_WRITE)

                if grants_altsec or grants_keycred or grants_gw:
                    principal = ace.principal_name or ace.sid
                    if grants_altsec or (grants_gw and not grants_keycred):
                        attr = "altSecurityIdentities"
                    else:
                        attr = "msDS-KeyCredentialLink"
                    if grants_gw:
                        attr = "GenericWrite (all properties)"
                    dangerous.append(f"{sam}: {principal} ({ace.sid}) → {attr}")
                    break

        if not dangerous:
            return

        self.add_finding(
            check="ESC14",
            severity=Severity.HIGH,
            title=f"ESC14: Write access to certificate mapping attributes on {len(dangerous)} privileged account(s)",
            description=(
                "Non-admin principals have WriteProperty rights on altSecurityIdentities or "
                "msDS-KeyCredentialLink (or GenericWrite) on privileged accounts (adminCount=1). "
                "An attacker with this access can map an attacker-controlled certificate to the "
                "victim account's altSecurityIdentities, then authenticate as the victim using "
                "that certificate — without enrolling through any template. "
                "This bypasses all template-level controls."
            ),
            details={
                "affected_accounts": dangerous[:30],
                "count": len(dangerous),
            },
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "https://attack.mitre.org/techniques/T1649/",
            ],
        )

    # ── ESC16: CA-level security extension suppression ────────────────────────

    def _check_esc16(self, ca: dict) -> None:
        """ESC16: CA-level szOID_NTDS_CA_SECURITY_EXT suppression — manual verification required."""
        self.add_finding(
            check="ESC16",
            severity=Severity.INFO,
            title=f"ESC16: Manual verification required for CA {ca['name']}",
            description=(
                f"CA {ca['name']!r} should be checked for CA-level suppression of the "
                "szOID_NTDS_CA_SECURITY_EXT extension (OID 1.3.6.1.4.1.311.25.2). "
                "If this extension is disabled at the CA level (via DisableExtensionList in the "
                "CA registry), ALL certificates issued by this CA will lack the NTDS SID extension, "
                "making every enrollable auth template on this CA equivalent to ESC9. "
                "This is the most severe CA misconfiguration — combined with ESC6, it enables "
                "impersonation of any user from any template. "
                "Cannot be confirmed via LDAP; requires CA server access. "
                "Verify with: certutil -v -config "
                f"'{ca['dns_host']}\\\\{ca['name']}' -getreg policy\\\\DisableExtensionList"
            ),
            details={
                "ca": ca["name"],
                "ca_host": ca["dns_host"],
                "check_command": (
                    f"certutil -v -config '{ca['dns_host']}\\{ca['name']}' "
                    "-getreg policy\\DisableExtensionList"
                ),
                "vulnerable_oid": "1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT)",
            },
            references=[
                "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7",
            ],
        )

    # ── enrollment right check ────────────────────────────────────────────────

    def _can_low_priv_enroll(self, tmpl: dict) -> bool:
        """Return True if a low-priv principal can enroll in this template."""
        sd_bytes = sd_bytes_from_entry(tmpl)
        if sd_bytes is None:
            return False
        try:
            sd = self._sdp.parse(sd_bytes)
        except Exception:
            return False

        for ace in sd.allow_aces():
            if not self._sdp.is_low_priv(ace.sid):
                continue
            if ace.mask & MASK_GENERIC_ALL:
                return True
            if ace.grants_extended_right(_GUID_ENROLL):
                return True
        return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _admin_sids(conn) -> frozenset[str]:
    skip = {"S-1-5-18", "S-1-5-9", "S-1-3-0"}
    try:
        dsid = conn.domain_sid
        skip.update({f"{dsid}-512", f"{dsid}-519", f"{dsid}-518",
                     "S-1-5-32-544"})
    except Exception:
        pass
    return frozenset(skip)


def _is_privileged_group_dn(group_dn: str, conn) -> bool:
    """Return True if the group DN corresponds to a well-known privileged group."""
    if not group_dn:
        return False
    dn_lower = group_dn.lower()
    # Check by known CN patterns
    privileged_cns = {
        "cn=domain admins",
        "cn=enterprise admins",
        "cn=schema admins",
        "cn=administrators",
        "cn=domain controllers",
        "cn=group policy creator owners",
    }
    for cn in privileged_cns:
        if dn_lower.startswith(cn + ","):
            return True
    # Check by RID via LDAP
    try:
        entries = conn.ldap_search(
            f"(distinguishedName={group_dn})",
            attributes=["objectSid"],
            base=group_dn,
            scope="BASE",
        )
        if entries:
            from maul.utils.parsers import sid_to_str
            raw_sid = entries[0].get("objectSid")
            if raw_sid and isinstance(raw_sid, bytes):
                sid_str = sid_to_str(raw_sid)
                domain_sid = conn.domain_sid
                for rid in ("-512", "-519", "-518", "-520", "-526", "-527"):
                    if sid_str == f"{domain_sid}{rid}":
                        return True
                if sid_str in {"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549",
                               "S-1-5-32-550", "S-1-5-32-551"}:
                    return True
    except Exception:
        pass
    return False


def _as_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _int(val, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _desc_mask(mask: int) -> str:
    parts = []
    if mask & MASK_GENERIC_ALL:  parts.append("GenericAll")
    if mask & 0x40000000:        parts.append("GenericWrite")
    if mask & 0x00040000:        parts.append("WriteDACL")
    if mask & 0x00080000:        parts.append("WriteOwner")
    if mask & 0x00000020:        parts.append("WriteProperty")
    return ", ".join(parts) or f"0x{mask:08x}"
