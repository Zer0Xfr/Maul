"""DCE/RPC helpers — SAMR, DRSUAPI, LSAT via impacket.

Current status: stub. The checks that require RPC (ESC6 CA flags, SAMR
enumeration fallback) are deferred to a future release. LDAP-based checks
cover the complete feature set without RPC.

Planned operations:
  - SAMR: enumerate local groups on DCs (cross-check against LDAP)
  - DRSUAPI: confirm DCSync rights by probing GetNCChanges (active check)
  - LSAT: LookupSids bulk resolution when LDAP SID queries are restricted
  - ICertAdminD: query CA flags (EDITF_ATTRIBUTESUBJECTALTNAME2 for ESC6)
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)


class RPCClient:
    """Placeholder for future RPC-based checks.

    All current checks use LDAP exclusively.  Instantiating this class
    or calling any method will raise NotImplementedError.
    """

    def __init__(self, conn) -> None:
        self._conn = conn

    def get_ca_security_flags(self, ca_name: str) -> int:
        """Query EDITF_ATTRIBUTESUBJECTALTNAME2 and other CA flags via ICertAdminD."""
        raise NotImplementedError("RPC-based CA flag check not yet implemented")

    def samr_enum_local_groups(self, target: str) -> list[str]:
        """Enumerate local group members via SAMR."""
        raise NotImplementedError("SAMR enumeration not yet implemented")
