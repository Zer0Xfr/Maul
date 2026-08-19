# Windows Authentication Internals: LDAP, LDAPS, SMB, and Channel Binding

A technical deep-dive into how authentication actually works at the protocol level in Active Directory environments, why certain combinations fail, and what Channel Binding Tokens fix.

---

## 1. NTLM Authentication — The Foundation

Every auth method discussed here (LDAP, SMB, HTTP) ultimately carries NTLM or Kerberos as the inner authentication mechanism. NTLM is the one that matters for understanding CBT, so let's start there.

### 1.1 The Three-Message Handshake

NTLM is a challenge-response protocol. It doesn't matter whether it's carried over SMB, LDAP, or HTTP — the three messages are the same:

```
Client                              Server
  |                                    |
  |--- NEGOTIATE_MESSAGE (Type 1) ---->|   "I want to authenticate, here are my capabilities"
  |                                    |
  |<-- CHALLENGE_MESSAGE (Type 2) ----|   "Here's a random 8-byte challenge, prove you know the password"
  |                                    |
  |--- AUTHENTICATE_MESSAGE (Type 3)->|   "Here's my proof (NTProofStr), computed over the challenge"
  |                                    |
```

### 1.2 Type 1 — NEGOTIATE

The client announces what it supports:
- NTLMSSP signature (`NTLMSSP\0`)
- Flags: UNICODE, NTLM, SEAL, SIGN, etc.
- Domain name (optional)
- Workstation name (optional)

### 1.3 Type 2 — CHALLENGE

The server responds with:
- An **8-byte ServerChallenge** (random nonce)
- **Target Info** (AV_PAIR list) — this is critical for CBT:
  - `MsvAvNbDomainName` — NetBIOS domain (e.g., "SHOWARE")
  - `MsvAvNbComputerName` — NetBIOS hostname (e.g., "MGMT-DC1")
  - `MsvAvDnsDomainName` — FQDN domain (e.g., "showare.local")
  - `MsvAvDnsComputerName` — FQDN host
  - `MsvAvTimestamp` — server time
  - `MsvAvFlags` — indicates if MIC is required
  - **`MsvAvChannelBindings`** (AV_ID 0x0A) — we'll come back to this

### 1.4 Type 3 — AUTHENTICATE

The client proves it knows the password. Here's where the math happens:

```
ResponseKeyNT = HMAC_MD5(MD4(password_utf16le), UPPER(username) + domain)

temp = 0x01 | 0x01 | Z(6) | Timestamp | ClientChallenge | Z(4) | ServerTargetInfo | Z(4)

NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)

NtChallengeResponse = NTProofStr || temp
```

The key insight: **ServerTargetInfo is included in the NTProofStr computation**. If the client modifies the TargetInfo (e.g., by adding or changing AV_PAIR entries), those modifications are signed into the proof. The server recomputes the same value — if they don't match, authentication fails with `STATUS_LOGON_FAILURE` / `invalidCredentials`.

This is how Channel Binding works — the client inserts a CBT hash into the TargetInfo before computing NTProofStr, and the server expects it to be there.

---

## 2. LDAP Authentication (Port 389)

### 2.1 How NTLM Bind Works Over LDAP

LDAP itself has no native auth mechanism. It uses **SASL** (Simple Authentication and Security Layer) to carry NTLM or Kerberos:

```
Client                                 DC (Port 389)
  |                                       |
  |--- BindRequest (SASL "GSS-SPNEGO") -->|  Contains NTLM Type 1 inside SPNEGO
  |                                       |
  |<-- BindResponse (SASL challenge) ----|  Contains NTLM Type 2 inside SPNEGO
  |                                       |
  |--- BindRequest (SASL response) ------>|  Contains NTLM Type 3 inside SPNEGO
  |                                       |
  |<-- BindResponse (success/failure) ---|
  |                                       |
```

The NTLM messages are wrapped in SPNEGO (Simple and Protected GSSAPI Negotiation) tokens, which are themselves carried inside LDAP SASL bind operations.

### 2.2 The Problem: No Encryption on Port 389

Plain LDAP (port 389) has no transport-level encryption. The NTLM exchange happens in cleartext at the network level. An attacker on the wire can:
1. Intercept the Type 2 challenge
2. Relay the Type 1/Type 3 to a different service (LDAP relay, SMB relay)
3. Perform man-in-the-middle attacks

### 2.3 LDAP Signing

"LDAP signing" means the DC requires **NTLM session signing** after the bind completes. After NTLM auth succeeds, both sides derive session keys:

```
SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
```

With signing enabled, every subsequent LDAP message includes an HMAC-MD5 signature computed with this key. This prevents tampering but NOT eavesdropping — the data is still plaintext.

When a DC has "LDAP server signing requirements = Require signing":
- The DC demands that the client negotiate and use signing
- ldap3's default NTLM bind does NOT negotiate signing
- Result: `strongerAuthRequired` error

### 2.4 How ldap3 Does NTLM (and Why It Fails)

ldap3's NTLM implementation (`ldap3/utils/ntlm.py`):
1. Constructs Type 1 with basic flags
2. Parses Type 2, extracts ServerChallenge and TargetInfo
3. Computes Type 3 using the raw `server_target_info_raw` verbatim
4. **Does NOT add MsvAvChannelBindings to the TargetInfo**
5. **Does NOT negotiate signing** (unless explicitly configured)

This means ldap3 fails on any DC that enforces either signing or channel binding.

---

## 3. LDAPS — LDAP Over TLS (Port 636)

### 3.1 Transport Layer

LDAPS wraps the entire LDAP protocol in TLS:

```
[TCP] → [TLS Record] → [LDAP BindRequest with NTLM]
```

The TLS handshake happens first (certificate exchange, cipher negotiation, key derivation), then LDAP messages flow inside the encrypted tunnel.

### 3.2 What TLS Provides

- **Confidentiality** — all LDAP traffic is encrypted
- **Integrity** — TLS MAC prevents tampering
- **Server authentication** — the DC presents an X.509 certificate

### 3.3 What TLS Does NOT Provide

TLS protects the transport, but the NTLM authentication inside is independent of TLS. This creates a gap:

- An attacker could terminate a TLS connection to the DC (as a man-in-the-middle)
- Forward the victim's NTLM Type 1/3 inside their own TLS session to the DC
- The DC sees valid NTLM credentials arriving over a valid TLS connection
- Authentication succeeds — the attacker is now authenticated as the victim

This is an **NTLM relay attack through TLS**. Channel Binding exists to prevent exactly this.

---

## 4. Channel Binding Tokens (CBT / EPA)

### 4.1 The Core Idea

Channel Binding cryptographically ties the NTLM authentication to the specific TLS session it's happening over. If an attacker relays NTLM through their own TLS connection, the binding won't match and auth fails.

### 4.2 How It Works — Step by Step

**Step 1: Compute the Channel Binding Token**

The client extracts the **server's TLS certificate** from the TLS handshake and computes:

```python
# Get the DER-encoded server certificate from the TLS socket
peer_cert_der = tls_socket.get_peer_certificate().to_cryptography().public_bytes(DER)

# Hash it with SHA-256 (for certs signed with SHA-256+; SHA-256 is the default for modern certs)
cert_hash = SHA256(peer_cert_der)

# Construct the "tls-server-end-point" channel binding per RFC 5929
application_data = b"tls-server-end-point:" + cert_hash
```

**Step 2: Build the GssChannelBindingsStruct (RFC 2744)**

```python
# This is the MD5 hash that goes into the NTLM TargetInfo
channel_binding_struct = b'\x00' * 8          # InitiatorAddrType + InitiatorAddress (empty)
channel_binding_struct += b'\x00' * 8          # AcceptorAddrType + AcceptorAddress (empty)
channel_binding_struct += len(application_data).to_bytes(4, 'little')
channel_binding_struct += application_data

channel_binding_value = MD5(channel_binding_struct)  # 16 bytes
```

**Step 3: Insert into NTLM TargetInfo**

Before computing NTProofStr, the client modifies the server's TargetInfo by adding:

```
AV_PAIR:
  AvId = MsvAvChannelBindings (0x000A)
  AvLen = 16
  Value = channel_binding_value (the MD5 from step 2)
```

**Step 4: Compute NTProofStr with the modified TargetInfo**

```python
temp = 0x0101 | Z(6) | Timestamp | ClientChallenge | Z(4) | modified_target_info | Z(4)
NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)
```

### 4.3 Server Verification

The DC performs the same computation:
1. It knows its own TLS certificate
2. It computes the same `tls-server-end-point` binding
3. It builds the same GssChannelBindingsStruct
4. It expects to find this exact MD5 in the client's TargetInfo (AV_ID 0x0A)
5. It recomputes NTProofStr — if the client used a different certificate (because they're relaying through their own TLS session), the hash won't match

### 4.4 Why This Stops Relay

```
Victim ←→ [Attacker's TLS (cert A)] ←→ [Attacker] ←→ [DC's TLS (cert B)] ←→ DC

Victim computes CBT from cert A (attacker's cert)
DC expects CBT from cert B (its own cert)
NTProofStr doesn't match → invalidCredentials
```

The attacker can't fix this because NTProofStr is an HMAC keyed with the victim's password hash — the attacker doesn't have it.

### 4.5 Channel Binding Policy Levels

The DC has three settings (registry: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding`):

| Value | Name | Behavior |
|-------|------|----------|
| 0 | Never | CBT not checked — relay works |
| 1 | When Supported | CBT checked only if client sends it — partial protection |
| 2 | Always | CBT required — relay blocked, clients without CBT get `invalidCredentials` |

Your DC has **Always** — which is why ldap3 fails (it never sends CBT) but impacket works (it computes and sends CBT).

---

## 5. SMB Authentication (Port 445)

### 5.1 SMB Session Setup

SMB authentication is conceptually similar to LDAP — it carries NTLM inside SPNEGO:

```
Client                                 DC (Port 445)
  |                                       |
  |--- SMB2 NEGOTIATE ------------------>|  Protocol negotiation (dialect, capabilities)
  |<-- SMB2 NEGOTIATE Response ----------|  Server capabilities, signing requirements
  |                                       |
  |--- SMB2 SESSION_SETUP (Type 1) ----->|  SPNEGO with NTLM NEGOTIATE
  |<-- SMB2 SESSION_SETUP (Type 2) -----|  SPNEGO with NTLM CHALLENGE (STATUS_MORE_PROCESSING_REQUIRED)
  |                                       |
  |--- SMB2 SESSION_SETUP (Type 3) ----->|  SPNEGO with NTLM AUTHENTICATE
  |<-- SMB2 SESSION_SETUP (success) ----|  Authenticated, session established
  |                                       |
```

### 5.2 SMB Signing

SMB signing is separate from LDAP signing:
- After NTLM auth, SessionBaseKey is derived (same formula as LDAP)
- A signing key is derived: `SigningKey = KDF(SessionBaseKey, "SMBSigningKey\0", PreauthIntegrityHash)`
- Every subsequent SMB2 packet has a 16-byte signature (AES-CMAC for SMB 3.x, HMAC-SHA256 for SMB 2.x)

When "Microsoft network server: Digitally sign communications (always)" is enabled, the DC rejects unsigned sessions.

### 5.3 Why SMB Auth Succeeds When LDAP Fails

SMB does NOT have Channel Binding in the same way:
- SMB channel binding would be to the SMB session itself (which isn't TLS-based unless using SMB over QUIC)
- Standard SMB on port 445 doesn't run over TLS
- The DC's LDAP channel binding policy **only affects LDAP** — it has no effect on SMB

This is why NXC with `nxc smb` works perfectly while `nxc ldap` or Maul's LDAP bind fails without CBT support.

### 5.4 The NetBIOS Domain Name Issue

The NTLM Type 3 includes `DomainNameFields` — the domain the client claims to authenticate to. For SMB:

```python
# What impacket sends in the Type 3 DomainName field:
domain_name = "SHOWARE"  # NetBIOS name from Type 2 TargetInfo (MsvAvNbDomainName)
```

Some DCs are strict about this field matching. When you pass the FQDN (`showare.local`) instead of the NetBIOS name (`SHOWARE`), the DC may reject it. Impacket's SMB client normally extracts the NetBIOS name from the Type 2 TargetInfo, but if you override it with an explicit domain parameter, it uses your value directly.

This is what Maul was doing wrong: passing `self.domain` (FQDN) to `smb.login()`. NXC either passes the short name or lets impacket auto-resolve it from the challenge.

---

## 6. The Full Picture — Why NXC Works and ldap3 Doesn't

### NXC's LDAP Path (what works)

```
1. Connect to DC:636 (TLS handshake)
2. Extract peer certificate from TLS socket
3. Compute tls-server-end-point: SHA256(cert_DER)
4. Build GssChannelBindingsStruct, MD5 it → 16-byte CBT
5. Store as self.channel_binding_value
6. Start NTLM:
   a. Send Type 1 via LDAP SASL bind
   b. Receive Type 2 (ServerChallenge + TargetInfo)
   c. Modify TargetInfo: insert AV_PAIR(0x0A, CBT)
   d. Compute NTProofStr over (ServerChallenge || modified_temp)
   e. Send Type 3
7. DC verifies: recomputes with its own cert → matches → success
```

### ldap3's NTLM Path (what breaks)

```
1. Connect to DC:636 (TLS handshake)
2. ❌ Does NOT extract peer certificate
3. ❌ Does NOT compute CBT
4. Start NTLM:
   a. Send Type 1
   b. Receive Type 2 (ServerChallenge + TargetInfo)
   c. ❌ Uses raw TargetInfo without adding MsvAvChannelBindings
   d. Compute NTProofStr over (ServerChallenge || unmodified_temp)
   e. Send Type 3
5. DC verifies: expects CBT in TargetInfo, doesn't find it
   → NTProofStr mismatch → invalidCredentials
```

### The Fix in Maul

```python
# Before: ldap3 (no CBT)
conn = ldap3.Connection(server, user="domain\\user", password=pw, authentication=NTLM)

# After: impacket (CBT computed automatically on LDAPS connect)
conn = impacket_ldap.LDAPConnection("ldaps://dc", baseDN, dstIp=dc)
conn.login(user, password, domain)  # CBT is in self.channel_binding_value
```

---

## 7. StartTLS vs LDAPS

### StartTLS (Port 389)

```
Client                                 DC (Port 389)
  |                                       |
  |--- [plaintext LDAP] ExtendedRequest ->|  OID 1.3.6.1.4.1.1466.20037 (StartTLS)
  |<-- ExtendedResponse (success) --------|
  |                                       |
  |=== TLS Handshake =====================|  Connection upgrades to TLS
  |                                       |
  |--- [encrypted] SASL Bind (NTLM) ---->|
```

- Same port (389), upgrades mid-connection
- Same CBT considerations apply (the TLS certificate is still available)
- Some DCs disable StartTLS entirely when they enforce LDAPS-only

### LDAPS (Port 636)

```
Client                                 DC (Port 636)
  |                                       |
  |=== TLS Handshake =====================|  TLS from the start
  |                                       |
  |--- [encrypted] SASL Bind (NTLM) ---->|
```

- Dedicated port, TLS from byte one
- No downgrade possibility
- Generally more reliable — this is what you should default to

### Why `strongerAuthRequired` on Port 389

When the DC has LDAP signing enforced AND you connect on port 389:
- If you don't negotiate signing AND you don't use StartTLS → rejected
- The DC wants either integrity protection (signing) or confidentiality (TLS)
- ldap3's default NTLM bind does neither → `strongerAuthRequired`

---

## 8. Putting It All Together

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transport Layer                                │
├──────────┬───────────────┬──────────────────────────────────────┤
│ SMB:445  │ LDAP:389      │ LDAPS:636                            │
│ (no TLS) │ (plain/STARTTLS)│ (TLS from start)                   │
├──────────┴───────────────┴──────────────────────────────────────┤
│                    Auth Container                                 │
│                    SPNEGO / GSSAPI                                │
├─────────────────────────────────────────────────────────────────┤
│                    NTLM / Kerberos                               │
│                    (Type 1 → Type 2 → Type 3)                   │
├─────────────────────────────────────────────────────────────────┤
│  Channel Binding (CBT)                                           │
│  ├── Only applies when TLS is present (LDAPS or StartTLS)       │
│  ├── Ties NTLM auth to the specific TLS session                 │
│  ├── Computed from server's TLS certificate                     │
│  └── Inserted into NTLM Type 3 TargetInfo as AV_PAIR 0x0A     │
├─────────────────────────────────────────────────────────────────┤
│  Signing                                                         │
│  ├── LDAP signing: HMAC on LDAP messages post-bind              │
│  ├── SMB signing: AES-CMAC/HMAC on SMB packets post-session    │
│  └── Both use keys derived from NTLM SessionBaseKey             │
└─────────────────────────────────────────────────────────────────┘
```

### Decision Matrix — What Works Where

| Scenario | SMB:445 | LDAP:389 (plain) | LDAP:389 (StartTLS) | LDAPS:636 |
|----------|---------|-------------------|---------------------|-----------|
| No signing, no CBT | works | works | works | works |
| Signing enforced | works (SMB signs anyway) | FAILS (strongerAuthRequired) | works (TLS = ok) | works |
| CBT: When Supported | works (N/A) | works (no TLS = no CBT needed) | works if client sends CBT | works if client sends CBT |
| CBT: Always | works (N/A) | works (no TLS = no CBT needed*) | FAILS without CBT | FAILS without CBT |

*Note: "CBT: Always" on port 389 without TLS is complex — the DC may still accept it if the bind doesn't use TLS, because CBT only applies to TLS-protected connections. But most DCs that enforce CBT also enforce signing, which blocks plain 389 anyway.

### What Maul Does Now

```
Password auth:
  --ldaps given → impacket LDAPS (CBT computed automatically) ✓
  port 389      → ldap3 with StartTLS attempt, then plain bind
                  (works if DC doesn't enforce CBT on StartTLS)

Pass-the-hash:
  Always → impacket LDAPS (CBT + hash auth) ✓

Kerberos:
  → ldap3 SASL/GSSAPI (CBT handled by GSSAPI layer) ✓

Pass-the-cert:
  → ldap3 LDAPS with client cert (EXTERNAL SASL, no NTLM = no CBT needed) ✓

SMB (for signing check):
  → impacket SMBConnection with NetBIOS domain name ✓
```

---

## 9. Key Takeaways

1. **CBT is a hash of the server's TLS certificate, inserted into NTLM Type 3.** It binds the NTLM proof to the specific TLS session, preventing relay through a different TLS connection.

2. **ldap3 does not implement CBT for NTLM.** This is a known gap. The library stores `client_channel_binding_unhashed` but never populates it during NTLM auth.

3. **impacket computes CBT automatically on LDAPS connections** (lines 152-170 in `impacket/ldap/ldap.py`). This is why NXC works.

4. **SMB is unaffected by LDAP channel binding policies.** They're completely independent protocols with independent security settings.

5. **"InvalidCredentials" doesn't always mean bad credentials.** When CBT is wrong or missing on a DC that enforces it, you get the same error — the DC can't distinguish "wrong password" from "wrong CBT" because both result in an NTProofStr mismatch.

6. **The signing/CBT enforcement chain:** A locked-down DC typically has both LDAP signing required AND channel binding Always. This means port 389 plain is dead (signing blocks it), and port 636 without CBT is dead (binding blocks it). You need a client that does LDAPS + CBT — which is what impacket provides.
