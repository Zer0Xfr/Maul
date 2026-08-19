"""DCE/RPC helpers — pipe probing, endpoint resolution, and RPC-based checks."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from maul.core.connection import ADConnection

log = logging.getLogger(__name__)


def probe_pipe(
    conn: "ADConnection",
    target: str,
    pipe: str,
    uuid_tuple: tuple[str, str],
    *,
    timeout: int = 10,
) -> bool:
    """Attempt to bind to a DCE/RPC interface on a named pipe.

    Returns True if the pipe exists and the interface is registered (bindable).
    Does NOT call any RPC methods — probe only.
    """
    from impacket.dcerpc.v5 import transport
    from impacket.uuid import uuidtup_to_bin

    string_binding = rf"ncacn_np:{target}[\PIPE\{pipe}]"
    rpctransport = transport.DCERPCTransportFactory(string_binding)
    rpctransport.set_dport(445)
    rpctransport.set_connect_timeout(timeout)
    rpctransport.setRemoteHost(target)

    _set_transport_creds(rpctransport, conn)

    try:
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(uuidtup_to_bin(uuid_tuple))
        dce.disconnect()
        return True
    except Exception as exc:
        log.debug("probe_pipe %s\\%s failed: %s", target, pipe, exc)
        return False


def probe_tcp_endpoint(
    conn: "ADConnection",
    target: str,
    uuid_tuple: tuple[str, str],
    *,
    timeout: int = 10,
) -> bool:
    """Resolve a DCE/RPC endpoint via EPM (port 135) and attempt to bind.

    Returns True if the endpoint is reachable and bindable.
    """
    from impacket.dcerpc.v5 import transport, epm
    from impacket.uuid import uuidtup_to_bin

    try:
        string_binding = rf"ncacn_ip_tcp:{target}[135]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(timeout)
        rpctransport.setRemoteHost(target)
        _set_transport_creds(rpctransport, conn)

        dce = rpctransport.get_dce_rpc()
        dce.connect()

        iface = uuidtup_to_bin(uuid_tuple)
        binding = epm.hept_map(target, iface, protocol="ncacn_ip_tcp", dce=dce)
        dce.disconnect()

        if not binding:
            return False

        rpctransport2 = transport.DCERPCTransportFactory(binding)
        rpctransport2.set_connect_timeout(timeout)
        rpctransport2.setRemoteHost(target)
        _set_transport_creds(rpctransport2, conn)

        dce2 = rpctransport2.get_dce_rpc()
        dce2.connect()
        dce2.bind(iface)
        dce2.disconnect()
        return True
    except Exception as exc:
        log.debug("probe_tcp_endpoint %s failed: %s", target, exc)
        return False


def check_pipe_exists(conn: "ADConnection", target: str, pipe_name: str) -> bool:
    """Check if a named pipe exists on IPC$ (e.g., 'DAV RPC Service').

    Uses SMB file open — no DCE/RPC bind. Returns True if the pipe is accessible.
    """
    try:
        smb = conn.get_smb_connection()
        tid = smb.connectTree("IPC$")
        fid = smb.openFile(tid, pipe_name)
        smb.closeFile(tid, fid)
        smb.disconnectTree(tid)
        return True
    except Exception as exc:
        log.debug("check_pipe_exists %s\\%s: %s", target, pipe_name, exc)
        return False


def _set_transport_creds(rpctransport, conn: "ADConnection") -> None:
    """Apply credentials from ADConnection to a DCE/RPC transport."""
    lmhash = nthash = ""
    if conn.nthash:
        if ":" in conn.nthash:
            lmhash, nthash = conn.nthash.split(":", 1)
        else:
            lmhash = ""
            nthash = conn.nthash

    rpctransport.set_credentials(
        conn.username or "",
        conn.password or "",
        conn.domain or "",
        lmhash,
        nthash,
        conn.aes_key or "",
    )

    if conn.use_kerberos:
        rpctransport.set_kerberos(True, kdcHost=conn.kdchost or conn.dc)
