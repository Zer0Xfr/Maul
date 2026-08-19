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
            detail = str(exc).lower()
            if "strongerauthrequ" in detail or "stronger" in detail:
                _err.print(
                    f"[bold red][!][/bold red] DC requires a secure channel for LDAP auth "
                    f"(strongerAuthRequired) — retry with [bold]--ldaps[/bold]"
                )
            else:
                _err.print(f"[bold red][!][/bold red] Authentication failed for {self.username}@{self.domain} — check credentials and that the user exists in this domain")
            log.debug("Bind error detail: %s", exc)
            sys.exit(1)
        except Exception as exc:
            detail = str(exc).lower()
            if "invalidcredentials" in detail or "52e" in detail:
                _err.print(f"[bold red][!][/bold red] Authentication failed for {self.username}@{self.domain} — check credentials")
            elif "strongerauthrequ" in detail or "stronger" in detail:
                _err.print(
                    f"[bold red][!][/bold red] DC requires a secure channel for LDAP auth "
                    f"(strongerAuthRequired) — retry with [bold]--ldaps[/bold]"
                )
            else:
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
        # Use impacket's LDAP client over LDAPS — it computes Channel Binding
        # Tokens (CBT) from the TLS certificate, which is required when the DC
        # enforces channel binding ("Always").  ldap3's NTLM doesn't do this.
        if self.use_ldaps:
            try:
                return self._connect_password_impacket()
            except ImportError:
                pass
            except Exception as exc:
                log.debug("impacket LDAPS bind failed, trying ldap3: %s", exc)

            conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password or "",
                authentication=NTLM,
                auto_bind=True,
            )
        else:
            # Try StartTLS on port 389 first — DCs that enforce signing/channel binding
            # reject plain NTLM binds with 'strongerAuthRequired'.
            conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=self.password or "",
                authentication=NTLM,
                auto_bind=False,
            )
            conn.open()
            try:
                conn.start_tls()
            except ldap3.core.exceptions.LDAPStartTLSError:
                pass  # TLS not available — fall through to plain bind
            conn.bind()
        if not conn.bound:
            conn.bind()
        return conn

    def _connect_password_impacket(self) -> ldap3.Connection:
        """LDAPS bind via impacket — supports channel binding tokens."""
        from impacket.ldap import ldap as impacket_ldap

        ldap_url = f"ldaps://{self.dc}"
        conn_impl = impacket_ldap.LDAPConnection(
            url=ldap_url,
            baseDN=self.root_dn if self._rootdse else domain_to_dn(self.domain),
            dstIp=self.dc,
        )
        conn_impl.login(
            self.username,
            self.password or "",
            self.domain,
        )

        server = ldap3.Server(self.dc, port=636, use_ssl=True, get_info=ldap3.ALL, connect_timeout=self.timeout)
        return _ImpacketLDAPShim(conn_impl, server)

    def _connect_nthash(self, server: ldap3.Server) -> ldap3.Connection:
        """NTLM pass-the-hash via impacket's LDAP client (ldap3 can't do PtH natively)."""
        if ":" in self.nthash:
            lm, nt = self.nthash.split(":", 1)
        else:
            lm = "aad3b435b51404eeaad3b435b51404ee"
            nt = self.nthash

        try:
            from impacket.ldap import ldap as impacket_ldap

            # Always use LDAPS for PtH — ensures channel binding works
            protocol = "ldaps" if self.use_ldaps else "ldaps"
            ldap_url = f"{protocol}://{self.dc}"
            base_dn = self.root_dn if self._rootdse else domain_to_dn(self.domain)
            conn_impl = impacket_ldap.LDAPConnection(ldap_url, base_dn, dstIp=self.dc)
            conn_impl.login(
                self.username,
                "",
                self.domain,
                lm,
                nt,
            )
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

        smb = SMBConnection(self.dc, self.dc, sess_port=445, timeout=10)

        # Use the short (NetBIOS) domain name from the NTLM challenge when available.
        # Many DCs reject the FQDN in the NTLMSSP Domain field — NXC works because
        # impacket extracts the NetBIOS domain from the server's challenge by default
        # when you pass an empty domain string.  Passing the FQDN overrides that logic
        # and can trigger STATUS_LOGON_FAILURE on strict DCs.
        smb_domain = self.domain.split(".")[0].upper()

        if self.use_kerberos:
            smb.kerberosLogin(self.username, self.password or "", self.domain, lmhash="", nthash="", aesKey=self.aes_key or "", kdcHost=self.kdchost or self.dc)
        elif self.nthash:
            lm, nt = ("aad3b435b51404eeaad3b435b51404ee", self.nthash) if ":" not in self.nthash else self.nthash.split(":", 1)
            smb.login(self.username, "", smb_domain, lmhash=lm, nthash=nt)
        else:
            smb.login(self.username, self.password or "", smb_domain)

        return smb


class _ImpacketLDAPShim:
    """Shim that wraps impacket's LDAPConnection to expose the ldap3 interface
    expected by ldap_client.py helpers (paged_search / search).

    Impacket handles channel binding tokens (CBT) and pass-the-hash natively,
    which ldap3's NTLM auth does not support.
    """

    def __init__(self, impl, server: ldap3.Server) -> None:
        self._impl = impl
        self.server = server
        self.bound = True
        self.result = {}
        self.entries = []
        self.response = []

    def unbind(self) -> None:
        try:
            self._impl.close()
        except Exception:
            pass

    def search(self, search_base="", search_filter="(objectClass=*)",
               search_scope=SUBTREE, attributes=None, get_operational_attributes=False,
               controls=None, **kwargs):
        from impacket.ldap.ldapasn1 import Scope, SimplePagedResultsControl, CONTROL_PAGEDRESULTS
        scope_map = {
            SUBTREE: Scope("wholeSubtree"),
            BASE: Scope("baseObject"),
            "BASE": Scope("baseObject"),
            "LEVEL": Scope("singleLevel"),
        }
        scope = scope_map.get(search_scope, Scope("wholeSubtree"))
        search_controls = None
        if controls:
            search_controls = [_build_impacket_control(c) for c in controls]

        attr_list = []
        if attributes and attributes != ldap3.ALL_ATTRIBUTES:
            attr_list = list(attributes) if not isinstance(attributes, list) else attributes

        results = self._impl.search(
            searchBase=search_base or None,
            scope=scope,
            searchFilter=search_filter,
            attributes=attr_list or None,
            searchControls=search_controls,
        )

        self.response = []
        self.entries = []
        for entry in results:
            converted = _impacket_entry_to_ldap3(entry)
            if converted:
                self.response.append(converted)
                self.entries.append(converted)
        return True

    @property
    def extend(self):
        return _ImpacketExtend(self)


class _ImpacketExtend:
    def __init__(self, shim):
        self.standard = _ImpacketStandard(shim)


class _ImpacketStandard:
    def __init__(self, shim):
        self._shim = shim

    def paged_search(self, search_base="", search_filter="(objectClass=*)",
                     search_scope=SUBTREE, attributes=None, paged_size=1000,
                     controls=None, generator=False, **kwargs):
        from impacket.ldap.ldapasn1 import Scope, SimplePagedResultsControl, CONTROL_PAGEDRESULTS

        scope_map = {
            SUBTREE: Scope("wholeSubtree"),
            BASE: Scope("baseObject"),
            "BASE": Scope("baseObject"),
            "LEVEL": Scope("singleLevel"),
        }
        scope = scope_map.get(search_scope, Scope("wholeSubtree"))

        search_controls = []
        paged_control = SimplePagedResultsControl()
        paged_control["size"] = paged_size
        search_controls.append(paged_control)
        if controls:
            search_controls.extend(_build_impacket_control(c) for c in controls)

        attr_list = []
        if attributes and attributes != ldap3.ALL_ATTRIBUTES:
            attr_list = list(attributes) if not isinstance(attributes, list) else attributes

        results = self._shim._impl.search(
            searchBase=search_base or None,
            scope=scope,
            searchFilter=search_filter,
            attributes=attr_list or None,
            searchControls=search_controls,
        )

        entries = []
        for entry in results:
            converted = _impacket_entry_to_ldap3(entry)
            if converted:
                entries.append(converted)

        if generator:
            return iter(entries)
        return entries


def _impacket_entry_to_ldap3(entry) -> dict | None:
    """Convert an impacket SearchResultEntry ASN.1 object to ldap3-style dict."""
    try:
        from impacket.ldap.ldapasn1 import SearchResultEntry
        if not isinstance(entry, SearchResultEntry):
            return None

        dn = str(entry["objectName"])
        attributes = {}
        for attr in entry["attributes"]:
            attr_type = str(attr["type"])
            vals = []
            for val in attr["vals"]:
                raw = bytes(val)
                try:
                    vals.append(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    vals.append(raw)
            if len(vals) == 1:
                attributes[attr_type] = vals[0]
            else:
                attributes[attr_type] = vals
        return {"type": "searchResEntry", "dn": dn, "attributes": attributes}
    except Exception:
        return None


def _build_impacket_control(ldap3_control):
    """Convert an ldap3-style control tuple to an impacket Control object."""
    from impacket.ldap.ldapasn1 import Control
    oid, criticality, value = ldap3_control
    ctrl = Control()
    ctrl["controlType"] = oid
    ctrl["criticality"] = criticality
    if value:
        ctrl["controlValue"] = value
    return ctrl
