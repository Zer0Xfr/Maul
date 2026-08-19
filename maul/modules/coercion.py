"""Coercion module — NTLM coercion endpoints, WebClient, ZeroLogon, RBCD feasibility."""

from __future__ import annotations

import logging

from maul.core.ldap_client import get_attr_first
from maul.modules import Finding, ModuleBase, Severity, register

log = logging.getLogger(__name__)

_COERCION_CHECKS = [
    {
        "name": "MS-RPRN",
        "attack": "PrinterBug / SpoolSample",
        "pipe": "spoolss",
        "uuid": ("12345678-1234-abcd-ef00-0123456789ab", "1.0"),
        "severity": Severity.LIKELY,
        "description": (
            "The Print Spooler service (MS-RPRN) is accessible. An attacker can call "
            "RpcRemoteFindFirstPrinterChangeNotificationEx to coerce the DC to authenticate "
            "back to an attacker-controlled host. Combined with relay (to LDAPS, ADCS, etc.) "
            "or unconstrained delegation capture, this is a direct escalation path."
        ),
    },
    {
        "name": "MS-EFSRPC",
        "attack": "PetitPotam",
        "pipe": "lsarpc",
        "uuid": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        "severity": Severity.LIKELY,
        "description": (
            "The Encrypting File System RPC interface (MS-EFSRPC) is accessible via lsarpc. "
            "An attacker can call EfsRpcOpenFileRaw to coerce NTLM authentication from the DC "
            "machine account. Relay to ADCS (ESC8/ESC11) or LDAPS for immediate escalation."
        ),
    },
    {
        "name": "MS-EFSRPC-ALT",
        "attack": "PetitPotam (efsrpc pipe)",
        "pipe": "efsrpc",
        "uuid": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
        "severity": Severity.LIKELY,
        "description": (
            "The alternate EFS RPC pipe (efsrpc) is accessible. Same attack as PetitPotam "
            "but via a different named pipe — some hardening only blocks lsarpc."
        ),
    },
    {
        "name": "MS-DFSNM",
        "attack": "DFSCoerce",
        "pipe": "netdfs",
        "uuid": ("4fc742e0-4a10-11cf-8273-00aa004ae673", "3.0"),
        "severity": Severity.LIKELY,
        "description": (
            "The Distributed File System Namespace Management interface (MS-DFSNM) is accessible. "
            "An attacker can call NetrDfsRemoveStdRoot to coerce NTLM authentication from the DC."
        ),
    },
    {
        "name": "MS-FSRVP",
        "attack": "ShadowCoerce",
        "pipe": "Fssagentrpc",
        "uuid": ("a8e0653c-2744-4389-a61d-7373df8b2292", "1.0"),
        "severity": Severity.POSSIBLE,
        "description": (
            "The File Server Remote VSS Protocol (MS-FSRVP) is accessible. "
            "An attacker can call IsPathSupported/IsPathShadowCopied to coerce NTLM authentication. "
            "Less common than PetitPotam/PrinterBug but works on file servers with VSS Agent."
        ),
    },
]

_ZEROLOGON_UUID = ("12345678-1234-abcd-ef00-01234567cffb", "1.0")
_ZEROLOGON_ATTEMPTS = 6


@register
class CoercionModule(ModuleBase):
    name = "coercion"
    description = "NTLM coercion endpoints, WebClient, ZeroLogon, RBCD feasibility"
    opsec_safe = False

    def run(self) -> list[Finding]:
        target = self.conn.dc

        self._check_coercion_pipes(target)
        self._check_webdav(target)
        self._check_zerologon(target)
        self._check_rbcd_feasibility()

        return self.findings

    def _check_coercion_pipes(self, target: str) -> None:
        from maul.core.rpc_client import probe_pipe

        available = []
        for check in _COERCION_CHECKS:
            result = probe_pipe(
                self.conn, target, check["pipe"], check["uuid"], timeout=10
            )
            if result:
                available.append(check)
                self.add_finding(
                    check=check["name"],
                    severity=check["severity"],
                    title=f"{check['attack']}: {check['pipe']} pipe accessible on {target}",
                    description=check["description"],
                    details={
                        "target": target,
                        "pipe": check["pipe"],
                        "interface": f"{check['uuid'][0]} v{check['uuid'][1]}",
                    },
                    references=[
                        "https://attack.mitre.org/techniques/T1187/",
                    ],
                )

        if not available:
            self.add_finding(
                check="CoercionEndpoints",
                severity=Severity.RECON,
                title=f"No coercion endpoints accessible on {target}",
                description="All tested coercion pipes (MS-RPRN, MS-EFSRPC, MS-DFSNM, MS-FSRVP) are inaccessible or disabled.",
            )

    def _check_webdav(self, target: str) -> None:
        from maul.core.rpc_client import check_pipe_exists

        if check_pipe_exists(self.conn, target, "DAV RPC SERVICE"):
            self.add_finding(
                check="WebClient",
                severity=Severity.LIKELY,
                title=f"WebClient service running on {target}",
                description=(
                    "The WebClient service (WebDAV) is running. This enables HTTP-based NTLM "
                    "authentication coercion without requiring port 445 access on the relay target. "
                    "An attacker can coerce auth to an attacker-controlled WebDAV UNC path and relay "
                    "the NTLM authentication to LDAPS or ADCS."
                ),
                details={"target": target, "pipe": "DAV RPC SERVICE"},
                references=[
                    "https://www.bussink.net/webclient-ntlm-relay/",
                ],
            )
        else:
            self.add_finding(
                check="WebClient",
                severity=Severity.RECON,
                title=f"WebClient service not running on {target}",
                description="The WebDAV client service is not active on this host.",
            )

    def _check_zerologon(self, target: str) -> None:
        try:
            vulnerable = self._zerologon_probe(target)
        except Exception as exc:
            log.debug("ZeroLogon check failed: %s", exc)
            self.add_finding(
                check="ZeroLogon",
                severity=Severity.RECON,
                title=f"ZeroLogon: could not test {target}",
                description=f"MS-NRPC endpoint unreachable or probe failed: {exc}",
            )
            return

        if vulnerable:
            self.add_finding(
                check="ZeroLogon",
                severity=Severity.PWNED,
                title=f"ZeroLogon (CVE-2020-1472): {target} is VULNERABLE",
                description=(
                    "The domain controller accepted a Netlogon authentication with zeroed credentials. "
                    "This is CVE-2020-1472 (ZeroLogon) — an unauthenticated attacker can reset the DC "
                    "machine account password to empty, then DCSync all domain credentials. "
                    "Immediate, unauthenticated domain compromise."
                ),
                details={"target": target, "cve": "CVE-2020-1472"},
                references=[
                    "https://attack.mitre.org/techniques/T1210/",
                    "https://www.secura.com/uploads/whitepapers/Zerologon.pdf",
                ],
            )
        else:
            self.add_finding(
                check="ZeroLogon",
                severity=Severity.RECON,
                title=f"ZeroLogon: {target} appears patched",
                description="DC rejected zeroed Netlogon credentials — CVE-2020-1472 patch is applied.",
            )

    def _zerologon_probe(self, target: str) -> bool:
        """Probe for ZeroLogon (CVE-2020-1472). Returns True if vulnerable."""
        from impacket.dcerpc.v5 import nrpc, epm, transport
        from impacket.dcerpc.v5.dtypes import NULL

        binding = epm.hept_map(
            target,
            nrpc.MSRPC_UUID_NRPC,
            protocol="ncacn_ip_tcp",
        )

        rpc_transport = transport.DCERPCTransportFactory(binding)
        rpc_transport.set_connect_timeout(10)
        rpc_transport.setRemoteHost(target)

        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        # Derive DC name from connection metadata
        dc_name = self._get_dc_netbios_name()
        dc_handle = "\\\\" + dc_name

        plaintext = b"\x00" * 8
        ciphertext = b"\x00" * 8
        flags = 0x212FFFFF

        for _ in range(_ZEROLOGON_ATTEMPTS):
            try:
                nrpc.hNetrServerReqChallenge(
                    dce, dc_handle + "\x00", dc_name + "\x00", plaintext
                )
                resp = nrpc.hNetrServerAuthenticate3(
                    dce,
                    dc_handle + "\x00",
                    dc_name + "$\x00",
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                    dc_name + "\x00",
                    ciphertext,
                    flags,
                )
                if resp["ErrorCode"] == 0:
                    dce.disconnect()
                    return True
            except nrpc.DCERPCSessionError as exc:
                if exc.get_error_code() == 0xC0000022:
                    continue
                else:
                    break
            except Exception:
                break

        dce.disconnect()
        return False

    def _get_dc_netbios_name(self) -> str:
        """Get the DC's NetBIOS computer name for Netlogon calls."""
        try:
            dcs = self.conn.domain_controllers
            for dc in dcs:
                name = get_attr_first(dc, "name")
                if name:
                    return str(name)
        except Exception:
            pass
        return self.conn.dc.split(".")[0].upper()

    def _check_rbcd_feasibility(self) -> None:
        """Check if RBCD attack is feasible (MachineAccountQuota > 0)."""
        try:
            entries = self.conn.ldap_search(
                "(objectClass=domain)",
                attributes=["ms-DS-MachineAccountQuota"],
                base=self.conn.root_dn,
                scope="BASE",
            )
        except Exception as exc:
            log.debug("RBCD feasibility check failed: %s", exc)
            return

        if not entries:
            return

        maq = get_attr_first(entries[0], "ms-DS-MachineAccountQuota")
        try:
            maq_val = int(maq) if maq is not None else 10
        except (TypeError, ValueError):
            maq_val = 10

        if maq_val > 0:
            self.add_finding(
                check="RBCDFeasibility",
                severity=Severity.POSSIBLE,
                title=f"RBCD attack feasible: MachineAccountQuota = {maq_val}",
                description=(
                    f"ms-DS-MachineAccountQuota is {maq_val} (default: 10). Any authenticated user "
                    "can create up to that many machine accounts. Combined with write access to a "
                    "target's msDS-AllowedToActOnBehalfOfOtherIdentity attribute (or coercion + relay), "
                    "this enables Resource-Based Constrained Delegation abuse: create a controlled "
                    "machine account, set RBCD on the target, then S4U2Self/S4U2Proxy to impersonate "
                    "any user to the target service."
                ),
                details={
                    "ms-DS-MachineAccountQuota": maq_val,
                    "attack_chain": "Create machine → Set RBCD on target → S4U2Proxy → Impersonate DA",
                },
                references=[
                    "https://attack.mitre.org/techniques/T1134/001/",
                    "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-target-exploitation",
                ],
            )
        else:
            self.add_finding(
                check="RBCDFeasibility",
                severity=Severity.RECON,
                title=f"MachineAccountQuota = {maq_val} (RBCD creation blocked)",
                description=(
                    "ms-DS-MachineAccountQuota is 0 — authenticated users cannot create machine "
                    "accounts. RBCD attack requires pre-existing control of a machine account."
                ),
                details={"ms-DS-MachineAccountQuota": maq_val},
            )
