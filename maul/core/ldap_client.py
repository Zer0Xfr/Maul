"""LDAP query helpers built on top of ldap3."""

from __future__ import annotations

import logging
from typing import Any, Generator

import ldap3
from ldap3 import Connection, SUBTREE, BASE, LEVEL

log = logging.getLogger(__name__)

# SD flags control — requests OWNER(1)+GROUP(2)+DACL(4)=7 in nTSecurityDescriptor
SD_CONTROL: list[tuple[str, bool, bytes]] = [
    ("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")
]


def paged_search(
    conn: Connection,
    search_base: str,
    search_filter: str,
    attributes: list[str] | str = ldap3.ALL_ATTRIBUTES,
    scope: str = SUBTREE,
    page_size: int = 1000,
    controls: list | None = None,
) -> Generator[dict[str, Any], None, None]:
    """Yield each search result entry as a dict, using LDAP paging.

    Handles the 1000-result server-side limit by issuing paged requests
    automatically.  Only ``searchResEntry`` entries are yielded — referrals
    and other response types are silently discarded.
    """
    kwargs: dict[str, Any] = dict(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=scope,
        attributes=attributes,
        paged_size=page_size,
        generator=True,
    )
    if controls is not None:
        kwargs["controls"] = controls
    for entry in conn.extend.standard.paged_search(**kwargs):
        if entry.get("type") == "searchResEntry":
            yield entry


def entry_to_dict(entry: dict[str, Any]) -> dict[str, Any]:
    """Flatten an ldap3 entry dict to ``{attr: value_or_list}``."""
    result: dict[str, Any] = {"dn": entry.get("dn", "")}
    attrs = entry.get("attributes", {})
    for key, val in attrs.items():
        result[key] = val
    return result


def get_single(
    conn: Connection,
    search_base: str,
    search_filter: str,
    attributes: list[str] | str = ldap3.ALL_ATTRIBUTES,
    scope: str = SUBTREE,
    controls: list | None = None,
) -> dict[str, Any] | None:
    """Return the first matching entry as a dict, or None."""
    for entry in paged_search(conn, search_base, search_filter, attributes, scope, controls=controls):
        return entry_to_dict(entry)
    return None


def search_all(
    conn: Connection,
    search_base: str,
    search_filter: str,
    attributes: list[str] | str = ldap3.ALL_ATTRIBUTES,
    scope: str = SUBTREE,
    page_size: int = 1000,
    controls: list | None = None,
) -> list[dict[str, Any]]:
    """Return all matching entries as a list of dicts (fully materialised)."""
    return [
        entry_to_dict(e)
        for e in paged_search(conn, search_base, search_filter, attributes, scope, page_size, controls)
    ]


def query_rootdse(conn: Connection) -> dict[str, Any]:
    """Query the rootDSE and return its attributes as a dict."""
    conn.search(
        search_base="",
        search_filter="(objectClass=*)",
        search_scope=BASE,
        attributes=ldap3.ALL_ATTRIBUTES,
        get_operational_attributes=True,
    )
    if conn.entries:
        raw = conn.response[0]
        return entry_to_dict(raw)
    return {}


def get_attr(entry: dict[str, Any], attr: str, default: Any = None) -> Any:
    """Case-insensitive attribute getter for ldap3 entry dicts."""
    if attr in entry:
        return entry[attr]
    lower = attr.lower()
    for k, v in entry.items():
        if k.lower() == lower:
            return v
    return default


def get_attr_first(entry: dict[str, Any], attr: str, default: Any = None) -> Any:
    """Get first value of a potentially multi-valued attribute."""
    val = get_attr(entry, attr, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val


def get_attr_bytes(entry: dict[str, Any], attr: str) -> bytes | None:
    """Get a binary attribute value as bytes."""
    val = get_attr(entry, attr)
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return val.encode("latin-1")
    return None


def build_sd_control() -> list[tuple[str, bool, bytes]]:
    """Return the LDAP_SERVER_SD_FLAGS_OID control for requesting nTSecurityDescriptor.

    Requests OWNER(1) + GROUP(2) + DACL(4) = 7, encoded as BER INTEGER.
    Pass the returned list directly to ldap3's ``controls`` parameter.
    """
    return SD_CONTROL
