"""Windows security descriptor parser using impacket's ldaptypes."""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from impacket.ldap import ldaptypes

from maul.utils.constants import (
    DOMAIN_RELATIVE_SIDS,
    EXTENDED_RIGHTS,
    WELL_KNOWN_SIDS,
)
from maul.utils.parsers import guid_to_str, sid_to_str

if TYPE_CHECKING:
    from maul.core.connection import ADConnection

log = logging.getLogger(__name__)

# ── ACE type constants (ACE_TYPE_MAP keys) ────────────────────────────────────
ACE_ACCESS_ALLOWED = 0
ACE_ACCESS_DENIED = 1
ACE_ACCESS_ALLOWED_OBJECT = 5
ACE_ACCESS_DENIED_OBJECT = 6
ACE_ACCESS_ALLOWED_CALLBACK = 9
ACE_ACCESS_DENIED_CALLBACK = 10
ACE_ACCESS_ALLOWED_CALLBACK_OBJECT = 11
ACE_ACCESS_DENIED_CALLBACK_OBJECT = 12

_ALLOW_TYPES = frozenset({ACE_ACCESS_ALLOWED, ACE_ACCESS_ALLOWED_OBJECT,
                           ACE_ACCESS_ALLOWED_CALLBACK, ACE_ACCESS_ALLOWED_CALLBACK_OBJECT})
_DENY_TYPES  = frozenset({ACE_ACCESS_DENIED, ACE_ACCESS_DENIED_OBJECT,
                           ACE_ACCESS_DENIED_CALLBACK, ACE_ACCESS_DENIED_CALLBACK_OBJECT})
_OBJECT_TYPES = frozenset({ACE_ACCESS_ALLOWED_OBJECT, ACE_ACCESS_DENIED_OBJECT,
                            ACE_ACCESS_ALLOWED_CALLBACK_OBJECT, ACE_ACCESS_DENIED_CALLBACK_OBJECT})

# ACE flag bits
ACE_FLAG_INHERITED         = 0x10
ACE_FLAG_CONTAINER_INHERIT = 0x02
ACE_FLAG_OBJECT_INHERIT    = 0x01
ACE_FLAG_INHERIT_ONLY      = 0x08

# Object ACE flags
OBJ_ACE_OBJECT_TYPE_PRESENT           = 0x1
OBJ_ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

# AD access mask bits
MASK_GENERIC_ALL    = 0x10000000
MASK_GENERIC_WRITE  = 0x40000000
MASK_GENERIC_READ   = 0x80000000
MASK_WRITE_DAC      = 0x00040000
MASK_WRITE_OWNER    = 0x00080000
MASK_DELETE         = 0x00010000
MASK_EXTENDED_RIGHT = 0x00000100
MASK_CREATE_CHILD   = 0x00000001
MASK_DELETE_CHILD   = 0x00000002
MASK_WRITE_PROPERTY = 0x00000020
MASK_SELF_WRITE     = 0x00000008
MASK_ALL_EXTENDED   = 0x00000100  # with no ObjectType = all extended rights

# Combined dangerous masks
MASK_DANGEROUS = MASK_GENERIC_ALL | MASK_GENERIC_WRITE | MASK_WRITE_DAC | MASK_WRITE_OWNER

# Well-known low-privilege SIDs (last element = RID suffix for domain-relative)
_LOW_PRIV_SIDS: frozenset[str] = frozenset({
    "S-1-1-0",    # Everyone
    "S-1-5-11",   # Authenticated Users
    "S-1-5-7",    # Anonymous Logon
    "S-1-2-0",    # Local
})
# Domain-relative low-priv RIDs: -513 Domain Users, -515 Domain Computers
_LOW_PRIV_RIDS: frozenset[str] = frozenset({"-513", "-515"})


# ── data classes ──────────────────────────────────────────────────────────────

@dataclass
class ParsedACE:
    ace_type: int
    ace_flags: int
    mask: int
    sid: str                              # S-1-5-... form
    principal_name: str                   # resolved display name
    object_type_guid: str | None          # GUID for extended right / schema attr
    object_type_name: str | None          # human-readable name for that GUID
    inherited_object_type_guid: str | None

    @property
    def is_allow(self) -> bool:
        return self.ace_type in _ALLOW_TYPES

    @property
    def is_deny(self) -> bool:
        return self.ace_type in _DENY_TYPES

    @property
    def is_object_ace(self) -> bool:
        return self.ace_type in _OBJECT_TYPES

    @property
    def is_inherited(self) -> bool:
        return bool(self.ace_flags & ACE_FLAG_INHERITED)

    def has_right(self, right_mask: int) -> bool:
        return bool(self.mask & right_mask)

    def grants_extended_right(self, guid: str) -> bool:
        """True if this ACE grants a specific extended right by GUID."""
        if not self.is_allow:
            return False
        if self.mask & MASK_GENERIC_ALL:
            return True
        if not (self.mask & MASK_EXTENDED_RIGHT):
            return False
        # All extended rights: MASK_EXTENDED_RIGHT with no ObjectType
        if not self.object_type_guid:
            return True
        return self.object_type_guid.lower() == guid.lower()

    def grants_write_property(self, guid: str) -> bool:
        """True if this ACE grants WriteProperty on a specific attribute GUID."""
        if not self.is_allow:
            return False
        if self.mask & MASK_GENERIC_ALL:
            return True
        if not (self.mask & MASK_WRITE_PROPERTY):
            return False
        if not self.object_type_guid:
            return True  # write all properties
        return self.object_type_guid.lower() == guid.lower()


@dataclass
class ParsedSD:
    owner_sid: str
    owner_name: str
    group_sid: str | None
    group_name: str | None
    aces: list[ParsedACE] = field(default_factory=list)

    def allow_aces(self) -> list[ParsedACE]:
        return [a for a in self.aces if a.is_allow]

    def explicit_aces(self) -> list[ParsedACE]:
        return [a for a in self.aces if not a.is_inherited]

    def aces_for_sid(self, sid: str) -> list[ParsedACE]:
        return [a for a in self.aces if a.sid == sid]

    def dangerous_allow_aces(self, exclude_inherited: bool = False) -> list[ParsedACE]:
        """Return ALLOW ACEs that carry dangerous rights (GenericAll, WriteDACL, etc.)."""
        result = []
        for ace in self.aces:
            if not ace.is_allow:
                continue
            if exclude_inherited and ace.is_inherited:
                continue
            if ace.mask & MASK_DANGEROUS:
                result.append(ace)
        return result


# ── parser ────────────────────────────────────────────────────────────────────

class SecurityDescriptorParser:
    """Parse Windows binary SDs and resolve SIDs/GUIDs to human-readable names."""

    def __init__(self, connection: "ADConnection | None" = None) -> None:
        self._conn = connection
        self._sid_cache: dict[str, str] = dict(WELL_KNOWN_SIDS)
        self._guid_cache: dict[str, str] = {k.lower(): v for k, v in EXTENDED_RIGHTS.items()}
        if connection is not None:
            self._populate_domain_sids()

    # ── cache population ──────────────────────────────────────────────────────

    def _populate_domain_sids(self) -> None:
        try:
            domain_sid = self._conn.domain_sid
            for suffix, name in DOMAIN_RELATIVE_SIDS.items():
                self._sid_cache[f"{domain_sid}{suffix}"] = name
        except Exception:
            pass

    def build_sid_cache(self) -> None:
        """Bulk-load all security principal SIDs from LDAP.  Call once before many parses."""
        if self._conn is None:
            return
        try:
            from maul.core.ldap_client import get_attr, get_attr_bytes
            entries = self._conn.ldap_search(
                "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
                attributes=["objectSid", "sAMAccountName"],
            )
            for entry in entries:
                raw = entry.get("objectSid")
                sam = entry.get("sAMAccountName") or ""
                if raw is None:
                    continue
                if isinstance(raw, list):
                    raw = raw[0] if raw else None
                if raw is None:
                    continue
                try:
                    sid_str = sid_to_str(raw) if isinstance(raw, bytes) else str(raw)
                    if sam:
                        self._sid_cache[sid_str] = str(sam)
                except Exception:
                    pass
        except Exception as exc:
            log.debug("SID cache build failed: %s", exc)

    def build_schema_guid_cache(self) -> None:
        """Load extended rights and schema attribute GUIDs from AD."""
        if self._conn is None:
            return
        # Extended rights from Configuration NC
        try:
            entries = self._conn.ldap_search(
                "(objectClass=controlAccessRight)",
                attributes=["rightsGuid", "displayName"],
                base=f"CN=Extended-Rights,{self._conn.config_dn}",
            )
            for entry in entries:
                guid = entry.get("rightsGuid") or ""
                name = entry.get("displayName") or ""
                if guid and name:
                    self._guid_cache[str(guid).lower()] = str(name)
        except Exception as exc:
            log.debug("Extended rights GUID cache failed: %s", exc)

        # Schema attribute GUIDs
        try:
            entries = self._conn.ldap_search(
                "(schemaIDGUID=*)",
                attributes=["schemaIDGUID", "lDAPDisplayName"],
                base=self._conn.schema_dn,
            )
            for entry in entries:
                raw = entry.get("schemaIDGUID")
                name = entry.get("lDAPDisplayName") or ""
                if raw is None or not name:
                    continue
                if isinstance(raw, list):
                    raw = raw[0] if raw else None
                if raw is None:
                    continue
                try:
                    g = guid_to_str(raw) if isinstance(raw, bytes) else str(raw)
                    self._guid_cache[g.lower()] = str(name)
                except Exception:
                    pass
        except Exception as exc:
            log.debug("Schema GUID cache failed: %s", exc)

    # ── resolution ────────────────────────────────────────────────────────────

    def resolve_sid(self, sid: str) -> str:
        """Return a display name for a SID string, querying LDAP on cache miss."""
        if sid in self._sid_cache:
            return self._sid_cache[sid]
        if self._conn is not None:
            try:
                encoded = _encode_sid_for_filter(sid)
                entries = self._conn.ldap_search(
                    f"(objectSid={encoded})",
                    attributes=["sAMAccountName"],
                )
                if entries:
                    name = entries[0].get("sAMAccountName") or sid
                    self._sid_cache[sid] = str(name)
                    return str(name)
            except Exception:
                pass
        self._sid_cache[sid] = sid
        return sid

    def resolve_guid(self, guid: str) -> str:
        """Return a name for an extended right / schema attribute GUID."""
        return self._guid_cache.get(guid.lower(), guid)

    # ── parsing ───────────────────────────────────────────────────────────────

    def parse(self, sd_bytes: bytes) -> ParsedSD:
        """Parse a binary Windows security descriptor."""
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)

        owner_sid = owner_name = group_sid = group_name = ""

        try:
            owner_sid = sd["OwnerSid"].formatCanonical()
            owner_name = self.resolve_sid(owner_sid)
        except Exception:
            pass

        try:
            group_sid = sd["GroupSid"].formatCanonical()
            group_name = self.resolve_sid(group_sid)
        except Exception:
            group_sid = None
            group_name = None

        aces: list[ParsedACE] = []
        try:
            dacl = sd["Dacl"]
            if dacl and dacl != b"":
                for raw_ace in dacl["Data"]:
                    parsed = self._parse_ace(raw_ace)
                    if parsed is not None:
                        aces.append(parsed)
        except Exception as exc:
            log.debug("DACL parse error: %s", exc)

        return ParsedSD(
            owner_sid=owner_sid,
            owner_name=owner_name,
            group_sid=group_sid,
            group_name=group_name,
            aces=aces,
        )

    def _parse_ace(self, ace_entry) -> ParsedACE | None:
        try:
            ace_type  = ace_entry["AceType"]
            ace_flags = ace_entry["AceFlags"]
            inner     = ace_entry["Ace"]

            mask = inner["Mask"]["Mask"]
            sid  = inner["Sid"].formatCanonical()
            principal_name = self.resolve_sid(sid)

            object_type_guid = object_type_name = inherited_object_type_guid = None

            if ace_type in _OBJECT_TYPES:
                flags = inner["Flags"]
                if flags & OBJ_ACE_OBJECT_TYPE_PRESENT:
                    raw_guid = inner["ObjectType"]
                    if len(raw_guid) == 16:
                        object_type_guid = guid_to_str(raw_guid)
                        object_type_name = self.resolve_guid(object_type_guid)
                if flags & OBJ_ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    raw_inh = inner["InheritedObjectType"]
                    if len(raw_inh) == 16:
                        inherited_object_type_guid = guid_to_str(raw_inh)

            return ParsedACE(
                ace_type=ace_type,
                ace_flags=ace_flags,
                mask=mask,
                sid=sid,
                principal_name=principal_name,
                object_type_guid=object_type_guid,
                object_type_name=object_type_name,
                inherited_object_type_guid=inherited_object_type_guid,
            )
        except Exception as exc:
            log.debug("ACE parse error: %s", exc)
            return None

    # ── convenience methods ───────────────────────────────────────────────────

    def is_low_priv(self, sid: str) -> bool:
        """Return True if the SID represents a low-privilege principal."""
        if sid in _LOW_PRIV_SIDS:
            return True
        if self._conn is not None:
            try:
                domain_sid = self._conn.domain_sid
                for rid in _LOW_PRIV_RIDS:
                    if sid == f"{domain_sid}{rid}":
                        return True
            except Exception:
                pass
        return False

    def find_low_priv_dangerous_aces(self, sd: ParsedSD) -> list[ParsedACE]:
        """Return ALLOW ACEs that grant dangerous rights to low-priv principals."""
        return [
            ace for ace in sd.aces
            if ace.is_allow and not ace.is_inherited
            and ace.mask & MASK_DANGEROUS
            and self.is_low_priv(ace.sid)
        ]


# ── helpers ───────────────────────────────────────────────────────────────────

def _encode_sid_for_filter(sid_str: str) -> str:
    """Encode a string SID as the LDAP filter hex-escaped binary form."""
    parts = sid_str.split("-")
    if len(parts) < 3 or parts[0] != "S":
        raise ValueError(f"Invalid SID string: {sid_str}")
    revision   = int(parts[1])
    authority  = int(parts[2])
    subs       = [int(p) for p in parts[3:]]
    data = bytes([revision, len(subs)]) + authority.to_bytes(6, "big")
    for s in subs:
        data += struct.pack("<I", s)
    return "".join(f"\\{b:02x}" for b in data)


def sd_bytes_from_entry(entry: dict[str, Any]) -> bytes | None:
    """Extract nTSecurityDescriptor bytes from an ldap3 entry dict."""
    from maul.core.ldap_client import get_attr
    raw = get_attr(entry, "nTSecurityDescriptor")
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, str):
        # ldap3 sometimes returns binary as latin-1 string
        try:
            return raw.encode("latin-1")
        except Exception:
            pass
    return None
