from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from maul.reporting.finding import Finding, Severity  # noqa: F401 — re-export for module convenience

if TYPE_CHECKING:
    from maul.core.connection import ADConnection

log = logging.getLogger(__name__)

_REGISTRY: dict[str, type["ModuleBase"]] = {}
_PRIVILEGED_SIDS_CACHE: frozenset[str] | None = None


def register(cls: type["ModuleBase"]) -> type["ModuleBase"]:
    """Class decorator that adds a module to the global registry."""
    _REGISTRY[cls.name] = cls
    return cls


def get_module(name: str) -> type["ModuleBase"] | None:
    return _REGISTRY.get(name)


def get_all_modules() -> dict[str, type["ModuleBase"]]:
    return dict(_REGISTRY)


def get_modules(names: list[str] | None = None) -> list[type["ModuleBase"]]:
    """Return module classes for the given names, or all modules if names is None."""
    if names is None:
        return list(_REGISTRY.values())
    result = []
    for name in names:
        mod = _REGISTRY.get(name)
        if mod is None:
            raise KeyError(f"Unknown module: {name!r}. Available: {list(_REGISTRY)}")
        result.append(mod)
    return result


def get_privileged_sids(conn: "ADConnection") -> frozenset[str]:
    """Return SIDs of privileged groups AND their individual members.

    Includes: SYSTEM, Enterprise DCs, Creator Owner, Domain Controllers,
    Domain Admins, Enterprise Admins, Schema Admins, Administrators,
    plus every direct member of those groups.

    Cached after first call per session.
    """
    global _PRIVILEGED_SIDS_CACHE
    if _PRIVILEGED_SIDS_CACHE is not None:
        return _PRIVILEGED_SIDS_CACHE

    from maul.core.ldap_client import get_attr, get_attr_first
    from maul.utils.parsers import sid_to_str

    skip = {
        "S-1-5-18",   # SYSTEM
        "S-1-5-9",    # Enterprise Domain Controllers
        "S-1-3-0",    # Creator Owner
        "S-1-5-32-544",  # Administrators (builtin)
    }

    try:
        dsid = conn.domain_sid
        skip.update({
            f"{dsid}-512",   # Domain Admins
            f"{dsid}-519",   # Enterprise Admins
            f"{dsid}-518",   # Schema Admins
            f"{dsid}-516",   # Domain Controllers
            f"{dsid}-520",   # Group Policy Creator Owners
        })

        priv_groups_filter = (
            "(|(sAMAccountName=Domain Admins)"
            "(sAMAccountName=Enterprise Admins)"
            "(sAMAccountName=Schema Admins)"
            "(sAMAccountName=Administrators))"
        )
        groups = conn.ldap_search(priv_groups_filter, attributes=["member"])

        member_dns = set()
        for g in groups:
            members = get_attr(g, "member")
            if members:
                if isinstance(members, list):
                    member_dns.update(str(m) for m in members)
                else:
                    member_dns.add(str(members))

        for dn in member_dns:
            try:
                entries = conn.ldap_search(
                    "(objectClass=*)",
                    attributes=["objectSid"],
                    base=dn,
                    scope="BASE",
                )
                if entries:
                    raw = get_attr_first(entries[0], "objectSid")
                    if isinstance(raw, bytes):
                        skip.add(sid_to_str(raw))
                    elif raw:
                        skip.add(str(raw))
            except Exception:
                continue
    except Exception as exc:
        log.debug("get_privileged_sids enrichment failed: %s", exc)

    _PRIVILEGED_SIDS_CACHE = frozenset(skip)
    return _PRIVILEGED_SIDS_CACHE


class ModuleBase:
    name: str = ""
    description: str = ""
    opsec_safe: bool = True  # if False, skipped with --opsec

    def __init__(self, connection: "ADConnection", options: dict | None = None) -> None:
        self.conn = connection
        self.options: dict = options or {}
        self.findings: list[Finding] = []

    def run(self) -> list[Finding]:
        """Execute all checks in this module. Return a list of Finding objects."""
        raise NotImplementedError(f"{self.__class__.__name__}.run() not implemented")

    def add_finding(self, **kwargs) -> None:
        self.findings.append(Finding(module=self.name, **kwargs))
