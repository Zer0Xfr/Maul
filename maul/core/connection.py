"""Central AD session object — authentication dispatch and LDAP/SMB session management."""

from __future__ import annotations

import logging
import sys
import traceback
from functools import cached_property
from typing import Any

import ldap3
from ldap3 import NTLM, SASL, KERBEROS, SUBTREE, BASE, ALL_ATTRIBUTES
from rich.console import Console as _Console

from maul.core.ldap_client import (
    paged_search,
    search_all,
    query_rootdse,
    entry_to_dict,
    get_attr,
    get_attr_first,
    get_attr_bytes,
)
from maul.utils.parsers import sid_to_str, domain_to_dn

log = logging.getLogger(__name__)


class AuthError(Exception):
    """Raised when LDAP authentication fails."""


class ConnectionError(Exception):  # noqa: A001 — shadows built-in intentionally
    """Raised when the LDAP connection cannot be established."""


class ADConnection:
    """Manages an authenticated LDAP session to an Active Directory domain.

    Modules receive an instance of this class and use it to query AD.  SMB
    connections are lazily initialised only when a module requests them.
    """

    def __init__(
        self,
        *,
        domain: str,
        dc: str | None = None,
        username: str | None = None,
        password: str | None = None,
        nthash: str | None = None,
        aes_key: str | None = None,
        pfx: str | None = None,
        pfx_pass: str | None = None,
        use_kerberos: bool = False,
        use_ldaps: bool = False,
        pass_the_cert: bool = False,
        kdchost: str | None = None,
        dns_server: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.domain = domain.lower()
        self.dc = dc
        self.username = username
        self.password = password
        self.nthash = nthash
        self.aes_key = aes_key
        self.pfx = pfx
        self.pfx_pass = pfx_pass
        self.use_kerberos = use_kerberos
        self.use_ldaps = use_ldaps
        self.pass_the_cert = pass_the_cert
        self.kdchost = kdchost
        self.timeout = timeout
        self.dns_server = dns_server

        self._ldap_conn: ldap3.Connection | None = None
        self._smb_conn = None
        self._rootdse: dict[str, Any] = {}

    # ── connection lifecycle ─────────────────────────────────────────────────

    def connect(self) -> None:
        """Establish the LDAP session and cache domain info from rootDSE."""
        _err = _Console(stderr=True)

        if not self.dc:
            try:
                self.dc = self._discover_dc()
            except ConnectionError as exc:
                _err.print(f"[bold red][!][/bold red] {exc}")
                sys.exit(1)

        port = 636 if self.use_ldaps else 389
        log.debug("Connecting to %s (%s)", self.dc, "LDAPS" if self.use_ldaps else "LDAP")
        try:
            self._ldap_conn = self._create_ldap_connection()
        except ldap3.core.exceptions.LDAPSocketOpenError:
            proto = "LDAPS (636)" if self.use_ldaps else "LDAP (389)"
            _err.print(f"[bold red][!][/bold red] Cannot reach {self.dc}:{port} — verify the DC IP and that {proto} is open")
            sys.exit(1)
        except ldap3.core.exceptions.LDAPStartTLSError:
            _err.print("[bold red][!][/bold red] STARTTLS failed — try using --ldaps for SSL or plain LDAP without TLS")
            sys.exit(1)
        except (ldap3.core.exceptions.LDAPBindError, AuthError) as exc:
            _err.print(f"[bold red][!][/bold red] Authentication failed for {self.username}@{self.domain} — check credentials and that the user exists in this domain")
            log.debug("Bind error detail: %s", exc)
            sys.exit(1)
        except Exception as exc:
            _err.print(f"[bold red][!][/bold red] Connection failed: {exc}")
            if log.isEnabledFor(logging.DEBUG):
                _err.print(traceback.format_exc())
            sys.exit(1)

        self._rootdse = query_rootdse(self._ldap_conn)
        log.debug("Connected. Root DN: %s", self.root_dn)

        # Warn if the DC serves a different domain than requested
        dc_dn = get_attr_first(self._rootdse, "defaultNamingContext")
        expected_dn = domain_to_dn(self.domain)
        if dc_dn and dc_dn.lower() != expected_dn.lower():
            _err.print(f"[bold yellow][!][/bold yellow] Warning: DC {self.dc} serves '{dc_dn}' but you specified domain '{self.domain}' ({expected_dn})")
            _err.print("[bold yellow][!][/bold yellow] You may be connecting to the wrong domain controller")

    def disconnect(self) -> None:
        if self._ldap_conn and self._ldap_conn.bound:
            self._ldap_conn.unbind()
        if self._smb_conn:
            try:
                self._smb_conn.logoff()
            except Exception:
                pass

    def __enter__(self) -> "ADConnection":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ── LDAP query interface (used by all modules) ───────────────────────────

    def ldap_search(
        self,
        search_filter: str,
        attributes: list[str] | str = ALL_ATTRIBUTES,
        base: str | None = None,
        scope: str = SUBTREE,
        page_size: int = 1000,
        controls: list | None = None,
    ) -> list[dict[str, Any]]:
        """Paged LDAP search returning a list of attribute dicts."""
        self._ensure_connected()
        return search_all(
            self._ldap_conn,
            base or self.root_dn,
            search_filter,
            attributes,
            scope,
            page_size,
            controls,
        )

    def ldap_search_generator(
        self,
        search_filter: str,
        attributes: list[str] | str = ALL_ATTRIBUTES,
        base: str | None = None,
        scope: str = SUBTREE,
        page_size: int = 1000,
        controls: list | None = None,
    ):
        """Paged LDAP search returning a generator of attribute dicts."""
        self._ensure_connected()
        for entry in paged_search(
            self._ldap_conn,
            base or self.root_dn,
            search_filter,
            attributes,
            scope,
            page_size,
            controls,
        ):
            yield entry_to_dict(entry)

    # ── lazy SMB connection ──────────────────────────────────────────────────

    def get_smb_connection(self):
        """Return (and lazily init) an impacket SMBConnection to the DC."""
        if self._smb_conn is not None:
            return self._smb_conn
        self._smb_conn = self._create_smb_connection()
        return self._smb_conn

    # ── cached domain info ───────────────────────────────────────────────────

    @cached_property
    def root_dn(self) -> str:
        val = get_attr_first(self._rootdse, "defaultNamingContext")
        if val:
            return str(val)
        return domain_to_dn(self.domain)

    @cached_property
    def config_dn(self) -> str:
        val = get_attr_first(self._rootdse, "configurationNamingContext")
        return str(val) if val else f"CN=Configuration,{self.root_dn}"

    @cached_property
    def schema_dn(self) -> str:
        val = get_attr_first(self._rootdse, "schemaNamingContext")
        return str(val) if val else f"CN=Schema,{self.config_dn}"

    @cached_property
    def forest_dn(self) -> str:
        val = get_attr_first(self._rootdse, "rootDomainNamingContext")
        return str(val) if val else self.root_dn

    @cached_property
    def domain_sid(self) -> str:
        """Query the domain root object for its objectSid."""
        self._ensure_connected()
        entries = self.ldap_search(
            "(objectClass=domain)",
            attributes=["objectSid"],
            base=self.root_dn,
            scope=BASE,
        )
        if not entries:
            raise ConnectionError("Could not retrieve domain objectSid")
        raw = get_attr_first(entries[0], "objectSid")
        if isinstance(raw, bytes):
            return sid_to_str(raw)
        return str(raw)

    @cached_property
    def domain_functional_level(self) -> int:
        """Return the msDS-Behavior-Version (domain functional level)."""
        self._ensure_connected()
        entries = self.ldap_search(
            "(objectClass=domain)",
            attributes=["msDS-Behavior-Version"],
            base=self.root_dn,
            scope=BASE,
        )
        if entries:
            val = get_attr_first(entries[0], "msDS-Behavior-Version")
            if val is not None:
                return int(val)
        return -1

    @cached_property
    def domain_controllers(self) -> list[dict[str, Any]]:
        """Return all DCs as a list of attribute dicts."""
        from maul.utils.ldap_filters import DOMAIN_CONTROLLERS
        return self.ldap_search(
            DOMAIN_CONTROLLERS,
            attributes=["name", "dNSHostName", "operatingSystem", "userAccountControl"],
        )

    # ── internals ────────────────────────────────────────────────────────────

    def _ensure_connected(self) -> None:
        if self._ldap_conn is None:
            raise ConnectionError("Not connected — call connect() first")

    def _discover_dc(self) -> str:
        """Resolve a DC for the domain via DNS SRV records."""
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            if self.dns_server:
                resolver.nameservers = [self.dns_server]

            qname = f"_ldap._tcp.dc._msdcs.{self.domain}"
            log.debug("DC discovery: querying %s", qname)
            answers = resolver.resolve(qname, "SRV")
            for rdata in sorted(answers, key=lambda r: (r.priority, r.weight)):
                host = str(rdata.target).rstrip(".")
                log.debug("DC discovery: found %s", host)
                return host
        except Exception as exc:
            log.debug("DC discovery failed: %s", exc)

        raise ConnectionError(
            f"Could not discover a DC for {self.domain!r}. "
            "Specify --dc explicitly."
        )

    def _create_ldap_connection(self) -> ldap3.Connection:
        port = 636 if self.use_ldaps else 389
        server = ldap3.Server(
            self.dc,
            port=port,
            use_ssl=self.use_ldaps,
            get_info=ldap3.ALL,
            connect_timeout=self.timeout,
        )

        if self.pass_the_cert and self.pfx:
            conn = self._connect_pass_the_cert(server)
        elif self.use_kerberos:
            conn = self._connect_kerberos(server)
        elif self.nthash:
            conn = self._connect_nthash(server)
        elif self.pfx and not self.pass_the_cert:
            conn = self._connect_pkinit(server)
        else:
            conn = self._connect_password(server)

        if not conn.bound:
            raise AuthError(
                f"LDAP bind to {self.dc} failed: {conn.result.get('description', 'unknown error')}"
            )

        return conn

    def _connect_password(self, server: ldap3.Server) -> ldap3.Connection:
        conn = ldap3.Connection(
            server,
            user=f"{self.domain}\\{self.username}",
            password=self.password or "",
            authentication=NTLM,
            auto_bind=ldap3.AUTO_BIND_NO_TLS if not self.use_ldaps else True,
        )
        if not conn.bound:
            conn.bind()
        return conn

    def _connect_nthash(self, server: ldap3.Server) -> ldap3.Connection:
        """NTLM pass-the-hash via impacket's LDAP client (ldap3 can't do PtH natively)."""
        # Normalise to LMHASH:NTHASH
        if ":" in self.nthash:
            lm, nt = self.nthash.split(":", 1)
        else:
            lm = "aad3b435b51404eeaad3b435b51404ee"
            nt = self.nthash

        try:
            from impacket.ldap import ldap as impacket_ldap
            from impacket.ldap import ldapasn1 as ldapasn1_impacket

            protocol = "ldaps" if self.use_ldaps else "ldap"
            ldap_url = f"{protocol}://{self.dc}"
            conn_impl = impacket_ldap.LDAPConnection(ldap_url, self.root_dn if self._rootdse else "")
            conn_impl.login(
                self.username,
                "",
                self.domain,
                lm,
                nt,
            )
            # Wrap in a shim so the rest of the code uses the same ldap3 interface
            return _ImpacketLDAPShim(conn_impl, server)
        except ImportError:
            raise AuthError("impacket is required for NT-hash authentication")
        except Exception as exc:
            raise AuthError(f"NT-hash LDAP bind failed: {exc}") from exc

    def _connect_kerberos(self, server: ldap3.Server) -> ldap3.Connection:
        conn = ldap3.Connection(
            server,
            authentication=SASL,
            sasl_mechanism=KERBEROS,
            auto_bind=True,
        )
        if not conn.bound:
            conn.bind()
        return conn

    def _connect_pkinit(self, server: ldap3.Server) -> ldap3.Connection:
        """Kerberos PKINIT using certipy's implementation."""
        try:
            from certipy.lib.pkinit import get_tgt_from_pfx
        except ImportError:
            raise AuthError("certipy-ad is required for PKINIT authentication")

        import os
        import tempfile

        tgt = get_tgt_from_pfx(self.pfx, self.pfx_pass, self.domain, self.username, self.kdchost or self.dc)
        # Write ccache to a temp file and set KRB5CCNAME
        ccache_file = tempfile.mktemp(suffix=".ccache")
        tgt.saveFile(ccache_file)
        os.environ["KRB5CCNAME"] = ccache_file
        return self._connect_kerberos(server)

    def _connect_pass_the_cert(self, server: ldap3.Server) -> ldap3.Connection:
        """LDAPS with client certificate (Schannel / Pass-the-Cert)."""
        import ssl
        import tempfile
        import os

        # Extract cert + key from PFX to temporary PEM files
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
            pfx_data = open(self.pfx, "rb").read()
            password = self.pfx_pass.encode() if self.pfx_pass else None
            private_key, certificate, _ = pkcs12.load_key_and_certificates(pfx_data, password)

            cert_pem = certificate.public_bytes(Encoding.PEM)
            key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

            cert_file = tempfile.mktemp(suffix=".crt")
            key_file = tempfile.mktemp(suffix=".key")
            with open(cert_file, "wb") as f:
                f.write(cert_pem)
            with open(key_file, "wb") as f:
                f.write(key_pem)
        except ImportError:
            raise AuthError("cryptography package is required for Pass-the-Cert authentication")

        tls = ldap3.Tls(
            local_certificate_file=cert_file,
            local_private_key_file=key_file,
            validate=ssl.CERT_NONE,
        )
        server_tls = ldap3.Server(self.dc, port=636, use_ssl=True, tls=tls, get_info=ldap3.ALL)
        conn = ldap3.Connection(server_tls, authentication=ldap3.SASL, sasl_mechanism="EXTERNAL", auto_bind=True)
        return conn

    def _create_smb_connection(self):
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            raise ConnectionError("impacket is required for SMB connections")

        smb = SMBConnection(self.dc, self.dc, timeout=10)

        if self.use_kerberos:
            smb.kerberosLogin(self.username, self.password or "", self.domain, lmhash="", nthash="", aesKey=self.aes_key or "", kdcHost=self.kdchost or self.dc)
        elif self.nthash:
            lm, nt = ("aad3b435b51404eeaad3b435b51404ee", self.nthash) if ":" not in self.nthash else self.nthash.split(":", 1)
            smb.login(self.username, "", self.domain, lmhash=lm, nthash=nt)
        else:
            smb.login(self.username, self.password or "", self.domain)

        return smb


class _ImpacketLDAPShim:
    """Minimal shim so impacket-backed PtH connections expose the ldap3 interface expected elsewhere.

    Only the subset of ldap3.Connection used by ldap_client helpers is implemented.
    This is a stopgap — most modules use ldap3's paged_search which won't work via this shim.
    TODO: replace with a proper impacket-backed paged search in ldap_client.
    """

    def __init__(self, impl, server: ldap3.Server) -> None:
        self._impl = impl
        self.server = server
        self.bound = True
        self.result = {}
        self.entries = []
        self.response = []

    def unbind(self) -> None:
        pass

    def search(self, *args, **kwargs):
        raise NotImplementedError("Full LDAP search via impacket shim not yet implemented")

    # ldap3.Connection.extend.standard.paged_search is accessed as an attribute chain;
    # modules should call conn.ldap_search() which goes through ADConnection, not this directly.
    class _extend:
        class standard:
            @staticmethod
            def paged_search(*args, **kwargs):
                raise NotImplementedError
    extend = _extend
