"""Certificate-based authentication helpers — PKINIT and Pass-the-Cert."""

from __future__ import annotations

import logging
import os
import tempfile

log = logging.getLogger(__name__)


def load_pfx(pfx_path: str, password: str | None = None) -> tuple:
    """Load a PFX/P12 file and return (private_key, certificate, extras)."""
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError:
        raise ImportError("cryptography package is required for PFX operations")

    with open(pfx_path, "rb") as fh:
        pfx_data = fh.read()
    pw = password.encode() if isinstance(password, str) else password
    return pkcs12.load_key_and_certificates(pfx_data, pw)


def pem_from_pfx(pfx_path: str, password: str | None = None) -> tuple[bytes, bytes]:
    """Extract PEM-encoded (cert, key) from a PFX file."""
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

    private_key, certificate, _ = load_pfx(pfx_path, password)
    cert_pem = certificate.public_bytes(Encoding.PEM)
    key_pem  = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return cert_pem, key_pem


def pem_files_from_pfx(pfx_path: str, password: str | None = None) -> tuple[str, str]:
    """Write PEM cert and key to temp files; return (cert_path, key_path).

    Caller is responsible for deleting the files.
    """
    cert_pem, key_pem = pem_from_pfx(pfx_path, password)
    cert_file = tempfile.mktemp(suffix=".crt")
    key_file  = tempfile.mktemp(suffix=".key")
    with open(cert_file, "wb") as fh:
        fh.write(cert_pem)
    with open(key_file, "wb") as fh:
        fh.write(key_pem)
    return cert_file, key_file


def get_tgt_from_pfx(
    pfx_path: str,
    pfx_pass: str | None,
    domain: str,
    username: str,
    dc: str,
) -> str:
    """Use certipy's PKINIT to get a TGT and save it as a ccache.

    Returns the path to the ccache file.
    """
    try:
        from certipy.lib.pkinit import get_tgt_from_pfx as certipy_pkinit
    except ImportError:
        raise ImportError("certipy-ad is required for PKINIT authentication")

    tgt = certipy_pkinit(pfx_path, pfx_pass, domain, username, dc)
    ccache_file = tempfile.mktemp(suffix=".ccache")
    tgt.saveFile(ccache_file)
    os.environ["KRB5CCNAME"] = ccache_file
    log.debug("PKINIT TGT saved to %s", ccache_file)
    return ccache_file


def generate_self_signed_cert(
    cn: str = "MaulKeyCredential",
    key_size: int = 2048,
    validity_days: int = 365,
) -> tuple:
    """Generate a self-signed RSA certificate.

    Returns (private_key, certificate) as cryptography objects.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.backends import default_backend
    from datetime import datetime, timedelta, timezone

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    return private_key, cert


def cert_to_pfx(
    private_key,
    certificate,
    password: str | None = None,
) -> bytes:
    """Serialise a private key + certificate to PFX bytes."""
    from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption, NoEncryption
    pw = password.encode() if isinstance(password, str) else password
    return pkcs12.serialize_key_and_certificates(
        name=b"maul",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(pw) if pw else NoEncryption(),
    )
