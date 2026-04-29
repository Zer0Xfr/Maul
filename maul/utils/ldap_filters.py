"""Pre-built LDAP filter strings for common AD queries."""

from __future__ import annotations


# ── generic helpers ──────────────────────────────────────────────────────────

def and_(*filters: str) -> str:
    """Join filters with AND."""
    inner = "".join(filters)
    return f"(&{inner})"


def or_(*filters: str) -> str:
    """Join filters with OR."""
    inner = "".join(filters)
    return f"(|{inner})"


def not_(f: str) -> str:
    return f"(!{f})"


def uac_bit(bit: int) -> str:
    """Match objects with a specific UAC bit set (LDAP_MATCHING_RULE_BIT_AND)."""
    return f"(userAccountControl:1.2.840.113556.1.4.803:={bit})"


def uac_bit_not(bit: int) -> str:
    return not_(uac_bit(bit))


# ── account state filters ────────────────────────────────────────────────────

ENABLED_USERS = and_("(objectClass=user)", uac_bit_not(0x0002))
DISABLED_USERS = and_("(objectClass=user)", uac_bit(0x0002))
DOMAIN_CONTROLLERS = and_("(objectCategory=computer)", uac_bit(0x2000))
ALL_COMPUTERS = "(objectClass=computer)"
ALL_USERS = "(objectClass=user)"
ALL_GROUPS = "(objectClass=group)"


# ── privilege / credential exposure filters ──────────────────────────────────

KERBEROASTABLE = and_(
    "(objectClass=user)",
    "(servicePrincipalName=*)",
    uac_bit_not(0x0002),  # not disabled
)

ASREPROASTABLE = and_(
    "(objectClass=user)",
    uac_bit(0x400000),    # DONT_REQUIRE_PREAUTH
    uac_bit_not(0x0002),  # not disabled
)

UNCONSTRAINED_DELEGATION = and_(
    "(objectClass=computer)",
    uac_bit(0x80000),      # TRUSTED_FOR_DELEGATION
    uac_bit_not(0x2000),   # exclude DCs (SERVER_TRUST_ACCOUNT)
)

CONSTRAINED_DELEGATION = "(msDS-AllowedToDelegateTo=*)"

RBCD = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"

ADMIN_COUNT = and_("(objectClass=user)", "(adminCount=1)", uac_bit_not(0x0002))

DONT_EXPIRE_PASSWORD = and_(
    "(objectClass=user)",
    uac_bit(0x10000),     # DONT_EXPIRE_PASSWORD
    uac_bit_not(0x0002),  # not disabled
)

SID_HISTORY = "(sIDHistory=*)"

UNIX_PASSWORD_ATTRS = "(|(unixUserPassword=*)(userPassword=*)(msSFU30Password=*))"

GMSA_ACCOUNTS = "(objectClass=msDS-GroupManagedServiceAccount)"

LAPS_LEGACY = "(ms-Mcs-AdmPwd=*)"
LAPS_NEW = "(msLAPS-Password=*)"


# ── ADCS filters ─────────────────────────────────────────────────────────────

CA_ENROLLMENT_SERVICES = "(objectClass=pKIEnrollmentService)"
CERTIFICATE_TEMPLATES = "(objectClass=pKICertificateTemplate)"


# ── application / infra detection ────────────────────────────────────────────

EXCHANGE_SERVERS = "(objectClass=msExchExchangeServer)"

GPO_CONTAINERS = "(objectClass=groupPolicyContainer)"

FINE_GRAINED_PWD_POLICY = "(objectClass=msDS-PasswordSettings)"

TRUSTED_DOMAINS = "(objectClass=trustedDomain)"

PASSWORD_SETTINGS_CONTAINER = "CN=Password Settings Container,CN=System"


# ── helpers for building filters at runtime ──────────────────────────────────

def dn_filter(attribute: str, dn: str) -> str:
    return f"({attribute}={_escape_dn(dn)})"


def group_member_filter(group_dn: str) -> str:
    """Return LDAP filter for direct members of a group."""
    return f"(memberOf={_escape_dn(group_dn)})"


def group_member_recursive_filter(group_dn: str) -> str:
    """Return LDAP filter for all members of a group (recursive, via LDAP_MATCHING_RULE_IN_CHAIN)."""
    return f"(memberOf:1.2.840.113556.1.4.1941:={_escape_dn(group_dn)})"


def inactive_accounts_filter(days: int = 90) -> str:
    """Return filter for accounts inactive for at least `days` days."""
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
    filetime = int(cutoff.timestamp() * 10_000_000) + 116_444_736_000_000_000
    return and_(
        "(objectClass=user)",
        uac_bit_not(0x0002),
        f"(lastLogonTimestamp<={filetime})",
    )


def _escape_dn(dn: str) -> str:
    """Minimal escaping of special chars in a DN used inside a filter value."""
    # Per RFC 4515: escape ( ) * \ NUL in filter values.
    # DNs used as filter values should also escape these chars.
    replacements = [("\\", "\\5c"), ("*", "\\2a"), ("(", "\\28"), (")", "\\29"), ("\x00", "\\00")]
    for char, escaped in replacements:
        dn = dn.replace(char, escaped)
    return dn
