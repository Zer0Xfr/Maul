"""Creds module — Kerberoast, AS-REP roast, SYSVOL credential exposure."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from base64 import b64decode

from maul.core.ldap_client import get_attr, get_attr_first
from maul.modules import Finding, ModuleBase, Severity, register
from maul.utils.ldap_filters import (
    ASREPROASTABLE,
    GMSA_ACCOUNTS,
    KERBEROASTABLE,
    UNIX_PASSWORD_ATTRS,
    and_,
    uac_bit_not,
)

log = logging.getLogger(__name__)

# AES-256 key Microsoft hardcoded for GPP cpassword encryption (CBC, zero IV)
_GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

# msDS-SupportedEncryptionTypes flag for AES
_ETYPE_AES128 = 0x08
_ETYPE_AES256 = 0x10
_ETYPE_RC4 = 0x04
_ETYPE_DES = 0x03  # DES_CBC_CRC | DES_CBC_MD5

# Regex for common cleartext password patterns in scripts
_SCRIPT_PASS_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?i)\bpassword\s*[=:]\s*["\']?([^\s"\'&;|,\r\n]{4,})', re.IGNORECASE),
    re.compile(r'(?i)\bpwd\s*[=:]\s*["\']?([^\s"\'&;|,\r\n]{4,})', re.IGNORECASE),
    re.compile(r'(?i)net\s+use\s+\S+\s+(\S+)\s+/user:', re.IGNORECASE),
    re.compile(r'(?i)-password\s+["\']?([^\s"\']{4,})', re.IGNORECASE),
    re.compile(r'(?i)ConvertTo-SecureString\s+["\']([^"\']{4,})["\']', re.IGNORECASE),
]


@register
class CredsModule(ModuleBase):
    name = "creds"
    description = "Kerberoastable accounts, AS-REP roastable accounts, SYSVOL credential exposure"
    opsec_safe = True  # enumeration-only; does not request tickets

    def run(self) -> list[Finding]:
        self._check_kerberoastable()
        self._check_asreproastable()
        self._check_sysvol()
        self._check_unix_passwords()
        self._check_gmsa()
        return self.findings

    # ── Kerberoast ────────────────────────────────────────────────────────────

    def _check_kerberoastable(self) -> None:
        entries = self.conn.ldap_search(
            KERBEROASTABLE,
            attributes=[
                "sAMAccountName", "distinguishedName", "servicePrincipalName",
                "msDS-SupportedEncryptionTypes", "adminCount", "pwdLastSet",
            ],
        )

        if not entries:
            self.add_finding(
                check="Kerberoast",
                severity=Severity.RECON,
                title="No Kerberoastable accounts",
                description="No enabled user accounts have a ServicePrincipalName set.",
            )
            return

        rc4_accounts: list[dict] = []
        aes_only_accounts: list[dict] = []

        for entry in entries:
            sam = str(get_attr_first(entry, "sAMAccountName") or entry.get("dn", "?"))
            spns = get_attr(entry, "servicePrincipalName") or []
            if not isinstance(spns, list):
                spns = [str(spns)]
            etypes = _int(get_attr_first(entry, "msDS-SupportedEncryptionTypes"))
            admin_count = _int(get_attr_first(entry, "adminCount"))

            # If etypes == 0 or RC4 bit set, RC4 is supported (easily crackable)
            supports_rc4 = (etypes == 0) or bool(etypes & _ETYPE_RC4)

            info = {
                "account": sam,
                "spns": spns,
                "enc_types": etypes,
                "rc4_allowed": supports_rc4,
                "admin_count": admin_count,
            }
            if supports_rc4:
                rc4_accounts.append(info)
            else:
                aes_only_accounts.append(info)

        if rc4_accounts:
            self.add_finding(
                check="Kerberoast",
                severity=Severity.LIKELY,
                title=f"Kerberoastable accounts (RC4): {len(rc4_accounts)}",
                description=(
                    f"{len(rc4_accounts)} account(s) are Kerberoastable with RC4 encryption. "
                    "An authenticated attacker can request TGS tickets and crack them offline. "
                    "RC4-based tickets are crackable with hashcat/JtR in seconds/minutes depending on password strength."
                ),
                details={
                    "count": len(rc4_accounts),
                    "accounts": [
                        f"{a['account']} (SPNs: {', '.join(a['spns'][:3])}{'…' if len(a['spns']) > 3 else ''})"
                        for a in rc4_accounts
                    ],
                    "privileged_accounts": [a["account"] for a in rc4_accounts if a["admin_count"]],
                },
                references=[
                    "https://attack.mitre.org/techniques/T1558/003/",
                    "https://www.tarlogic.com/blog/how-to-attack-kerberos/",
                ],
            )

        if aes_only_accounts:
            self.add_finding(
                check="KerberoastAES",
                severity=Severity.POSSIBLE,
                title=f"Kerberoastable accounts (AES-only): {len(aes_only_accounts)}",
                description=(
                    f"{len(aes_only_accounts)} account(s) are Kerberoastable but only support AES. "
                    "AES tickets are still offline-crackable but significantly slower than RC4."
                ),
                details={
                    "count": len(aes_only_accounts),
                    "accounts": [a["account"] for a in aes_only_accounts],
                },
                references=["https://attack.mitre.org/techniques/T1558/003/"],
            )

    # ── AS-REP roast ──────────────────────────────────────────────────────────

    def _check_asreproastable(self) -> None:
        entries = self.conn.ldap_search(
            ASREPROASTABLE,
            attributes=[
                "sAMAccountName", "distinguishedName",
                "msDS-SupportedEncryptionTypes", "adminCount",
            ],
        )

        if not entries:
            self.add_finding(
                check="ASREPRoast",
                severity=Severity.RECON,
                title="No AS-REP roastable accounts",
                description="No enabled user accounts have DONT_REQUIRE_PREAUTH set.",
            )
            return

        names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]
        privileged = [
            str(get_attr_first(e, "sAMAccountName") or "?")
            for e in entries
            if _int(get_attr_first(e, "adminCount")) == 1
        ]

        sev = Severity.PWNED if privileged else Severity.LIKELY

        self.add_finding(
            check="ASREPRoast",
            severity=sev,
            title=f"AS-REP roastable accounts: {len(entries)}",
            description=(
                f"{len(entries)} account(s) have Kerberos pre-authentication disabled "
                "(DONT_REQUIRE_PREAUTH). An unauthenticated attacker can request an AS-REP and "
                "crack it offline — no valid credential required."
                + (f" {len(privileged)} privileged account(s) included." if privileged else "")
            ),
            details={
                "count": len(entries),
                "accounts": names,
                "privileged_accounts": privileged,
            },
            references=["https://attack.mitre.org/techniques/T1558/004/"],
        )

    # ── SYSVOL credential exposure ────────────────────────────────────────────

    def _check_sysvol(self) -> None:
        try:
            smb_conn = self.conn.get_smb_connection()
        except Exception as exc:
            log.debug("SMB unavailable for SYSVOL scan: %s", exc)
            self.add_finding(
                check="SYSVOLScan",
                severity=Severity.RECON,
                title="SYSVOL scan skipped — SMB unavailable",
                description=f"Could not establish SMB connection for SYSVOL credential scan: {exc}",
            )
            return

        from maul.core.smb_client import SMBClient
        smb = SMBClient(smb_conn)

        gpp_findings: list[dict] = []
        script_findings: list[dict] = []

        try:
            for gpo_guid, file_path, content in smb.iter_gpo_credential_files(self.conn.domain):
                filename = file_path.rsplit("\\", 1)[-1]

                # GPP XML files
                if filename.lower().endswith(".xml"):
                    hits = _parse_gpp_xml(content)
                    for hit in hits:
                        gpp_findings.append({
                            "gpo": gpo_guid,
                            "file": file_path,
                            "type": hit["type"],
                            "username": hit.get("username"),
                            "decrypted": hit.get("decrypted"),
                            "cpassword": hit.get("cpassword"),
                        })
                else:
                    # Script files — search for cleartext patterns
                    hits = _scan_script_for_credentials(content, file_path)
                    script_findings.extend(hits)

        except Exception as exc:
            log.debug("SYSVOL scan error: %s", exc)

        if gpp_findings:
            # Split into decrypted vs not
            decrypted = [f for f in gpp_findings if f.get("decrypted")]
            encrypted = [f for f in gpp_findings if not f.get("decrypted")]

            self.add_finding(
                check="GPPCredentials",
                severity=Severity.PWNED,
                title=f"GPP credentials found in SYSVOL: {len(gpp_findings)} item(s)",
                description=(
                    "Group Policy Preferences (GPP) stored credentials were found in SYSVOL. "
                    "Microsoft published the AES decryption key (MS14-025). "
                    "All domain users can read SYSVOL, making these passwords trivially recoverable."
                ),
                details={
                    "total": len(gpp_findings),
                    "decrypted_passwords": [
                        f"{f['type']} / {f['username']}: {f['decrypted']}"
                        for f in decrypted
                    ],
                    "files": list({f["file"] for f in gpp_findings}),
                },
                references=[
                    "https://attack.mitre.org/techniques/T1552/006/",
                    "https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30",
                ],
            )

        if script_findings:
            self.add_finding(
                check="SYSVOLScriptCredentials",
                severity=Severity.LIKELY,
                title=f"Potential credentials in SYSVOL scripts: {len(script_findings)} match(es)",
                description=(
                    "Script files in SYSVOL contain patterns that may indicate embedded credentials. "
                    "Manual review required to confirm."
                ),
                details={
                    "matches": [
                        f"{f['file']}: {f['match']}"
                        for f in script_findings[:20]
                    ]
                },
                references=["https://attack.mitre.org/techniques/T1552/006/"],
            )

        if not gpp_findings and not script_findings:
            self.add_finding(
                check="SYSVOLScan",
                severity=Severity.RECON,
                title="No credentials found in SYSVOL",
                description="SYSVOL was scanned — no GPP cpassword entries or script credentials found.",
            )

    # ── Unix/legacy password attributes ──────────────────────────────────────

    def _check_unix_passwords(self) -> None:
        entries = self.conn.ldap_search(
            UNIX_PASSWORD_ATTRS,
            attributes=["sAMAccountName", "distinguishedName", "unixUserPassword", "userPassword"],
        )
        if not entries:
            return

        names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]

        self.add_finding(
            check="UnixPasswordAttributes",
            severity=Severity.LIKELY,
            title=f"Unix/legacy password attributes set: {len(entries)} account(s)",
            description=(
                "AD accounts with unixUserPassword, userPassword, or msSFU30Password set "
                "store passwords in reversible or weakly-hashed form for Unix/NIS integration. "
                "These attributes are readable by authenticated users."
            ),
            details={"count": len(entries), "accounts": names},
            references=["https://attack.mitre.org/techniques/T1552/001/"],
        )

    # ── gMSA ──────────────────────────────────────────────────────────────────

    def _check_gmsa(self) -> None:
        entries = self.conn.ldap_search(
            GMSA_ACCOUNTS,
            attributes=["sAMAccountName", "distinguishedName", "msDS-ManagedPasswordInterval"],
        )
        if not entries:
            return

        names = [
            str(get_attr_first(e, "sAMAccountName") or e.get("dn", "?"))
            for e in entries
        ]

        self.add_finding(
            check="gMSAAccounts",
            severity=Severity.RECON,
            title=f"Group Managed Service Accounts: {len(entries)}",
            description=(
                f"{len(entries)} gMSA(s) found. "
                "gMSA password readability depends on the msDS-GroupMSAMembership ACL. "
                "ACL analysis (Phase 3) will identify which principals can retrieve the managed password."
            ),
            details={"count": len(entries), "gmsa_accounts": names},
        )


# ── GPP XML parsing ───────────────────────────────────────────────────────────

def _parse_gpp_xml(content: bytes) -> list[dict]:
    """Parse a GPP XML file and return credential entries (with decrypted passwords where possible)."""
    results = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return results

    for elem in root.iter():
        props = elem.get("Properties") or {}
        # The actual properties are sub-elements, not the Properties attribute
        # Parse from sub-elements instead
        for sub in elem:
            cpassword = sub.get("cpassword") or sub.get("cPassword")
            if not cpassword:
                continue
            username = sub.get("userName") or sub.get("username") or sub.get("name") or ""
            decrypted: str | None = None
            try:
                decrypted = _decrypt_cpassword(cpassword)
            except Exception:
                pass

            results.append({
                "type": elem.tag,
                "username": username,
                "cpassword": cpassword,
                "decrypted": decrypted,
            })

    # Also search at the top level (some older files have it directly on elements)
    for elem in root.iter():
        cpassword = elem.get("cpassword") or elem.get("cPassword")
        if not cpassword:
            continue
        # Check we haven't already found this
        already = any(r["cpassword"] == cpassword for r in results)
        if already:
            continue
        username = elem.get("userName") or elem.get("username") or elem.get("name") or ""
        decrypted = None
        try:
            decrypted = _decrypt_cpassword(cpassword)
        except Exception:
            pass
        results.append({
            "type": elem.tag,
            "username": username,
            "cpassword": cpassword,
            "decrypted": decrypted,
        })

    return results


def _decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword using Microsoft's hardcoded AES key."""
    from Crypto.Cipher import AES

    # Add base64 padding
    missing = len(cpassword) % 4
    if missing:
        cpassword += "=" * (4 - missing)

    encrypted = b64decode(cpassword)
    cipher = AES.new(_GPP_AES_KEY, AES.MODE_CBC, iv=bytes(16))
    decrypted = cipher.decrypt(encrypted)

    # Remove PKCS7 padding
    pad_len = decrypted[-1]
    if isinstance(pad_len, int) and 1 <= pad_len <= 16:
        decrypted = decrypted[:-pad_len]

    return decrypted.decode("utf-16-le").rstrip("\x00")


def _scan_script_for_credentials(content: bytes, file_path: str) -> list[dict]:
    """Search script file content for common credential patterns."""
    from maul.core.smb_client import _SCRIPT_PASS_PATTERNS

    results = []
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return results

    for pattern in _SCRIPT_PASS_PATTERNS:
        for m in pattern.finditer(text):
            matched = m.group(1) if m.lastindex else m.group(0)
            # Skip obviously non-secret matches
            if len(matched) < 4 or matched.lower() in ("password", "pass", "secret", "changeme"):
                continue
            results.append({"file": file_path, "match": f"…{m.group(0)[:80]}…"})
            break  # one hit per pattern per file is enough

    return results


def _int(val, default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
