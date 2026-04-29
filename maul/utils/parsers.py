from __future__ import annotations

import struct
from datetime import datetime, timezone

# 100ns intervals between 1601-01-01 and 1970-01-01
_FILETIME_EPOCH_DIFF = 116_444_736_000_000_000
# Sentinel value for "never" in AD (max int64)
_FILETIME_NEVER = 0x7FFFFFFFFFFFFFFF
_FILETIME_NEVER_NEG = -9_223_372_036_854_775_808


def filetime_to_datetime(filetime: int) -> datetime | None:
    """Convert Windows FILETIME (100ns intervals since 1601-01-01 UTC) to datetime."""
    if filetime in (0, _FILETIME_NEVER, _FILETIME_NEVER_NEG):
        return None
    try:
        unix_ts = (filetime - _FILETIME_EPOCH_DIFF) / 10_000_000
        return datetime.fromtimestamp(unix_ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def filetime_to_days(filetime: int) -> int | None:
    """Convert a negative FILETIME interval (e.g. maxPwdAge) to a positive day count."""
    if filetime in (0, _FILETIME_NEVER, _FILETIME_NEVER_NEG):
        return None
    # AD stores intervals as negative 100ns values
    ticks = abs(filetime)
    return ticks // 10_000_000 // 86_400


def sid_to_str(sid_bytes: bytes) -> str:
    """Convert binary SID to its string representation (S-1-X-...)."""
    if len(sid_bytes) < 8:
        raise ValueError(f"SID too short: {len(sid_bytes)} bytes")
    revision = sid_bytes[0]
    sub_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder="big")
    if len(sid_bytes) < 8 + sub_count * 4:
        raise ValueError(f"SID data truncated: expected {8 + sub_count * 4} bytes")
    subs = struct.unpack_from(f"<{sub_count}I", sid_bytes, 8)
    return f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs)


def guid_to_str(guid_bytes: bytes) -> str:
    """Convert binary GUID (mixed-endian) to its canonical string form."""
    if len(guid_bytes) != 16:
        raise ValueError(f"GUID must be 16 bytes, got {len(guid_bytes)}")
    data1, data2, data3 = struct.unpack_from("<IHH", guid_bytes, 0)
    data4 = guid_bytes[8:]
    return (
        f"{data1:08x}-{data2:04x}-{data3:04x}-"
        f"{data4[0]:02x}{data4[1]:02x}-"
        f"{''.join(f'{b:02x}' for b in data4[2:])}"
    )


def parse_uac_flags(uac: int) -> list[str]:
    """Return list of UAC flag names set in the given integer."""
    from maul.utils.constants import UAC_FLAGS
    return [name for bit, name in UAC_FLAGS.items() if uac & bit]


def dn_to_domain(dn: str) -> str:
    """Extract domain FQDN from a Distinguished Name.

    ``DC=ellingson,DC=com`` → ``ellingson.com``
    """
    parts = [
        p.split("=", 1)[1]
        for p in dn.split(",")
        if p.strip().upper().startswith("DC=")
    ]
    return ".".join(parts)


def domain_to_dn(domain: str) -> str:
    """Convert domain FQDN to its LDAP DN form.

    ``ellingson.com`` → ``DC=ellingson,DC=com``
    """
    return ",".join(f"DC={part}" for part in domain.split("."))


def parse_samaccounttype(value: int) -> str:
    """Return a human-readable string for a sAMAccountType value."""
    _types = {
        0x10000000: "Domain Object",
        0x10000001: "Group Object",
        0x10000002: "Non-Security Group Object",
        0x20000000: "Alias Object",
        0x20000001: "Non-Security Alias Object",
        0x30000000: "User Object",
        0x30000001: "Machine Account",
        0x30000002: "Trust Account",
        0x40000000: "App Basic Group",
        0x40000001: "App Query Group",
        0x7FFFFFFF: "Unknown",
    }
    return _types.get(value, f"Unknown (0x{value:x})")
