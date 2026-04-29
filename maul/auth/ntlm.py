"""NTLM credential helpers."""

from __future__ import annotations

_EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"


def parse_hash(hash_str: str) -> tuple[str, str]:
    """Parse a hash string into (lmhash, nthash).

    Accepts: NTHASH only, LMHASH:NTHASH, or :NTHASH.
    """
    if not hash_str:
        return _EMPTY_LM, ""
    if ":" in hash_str:
        lm, nt = hash_str.split(":", 1)
        return (lm or _EMPTY_LM), nt
    return _EMPTY_LM, hash_str


def is_valid_nthash(h: str) -> bool:
    """Return True if h looks like a valid NT hash (32 hex chars)."""
    if not h:
        return False
    clean = h.split(":")[-1] if ":" in h else h
    return len(clean) == 32 and all(c in "0123456789abcdefABCDEF" for c in clean)
