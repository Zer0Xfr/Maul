"""High-level SMB helpers for SYSVOL/share access, built on impacket."""

from __future__ import annotations

import logging
import re
from io import BytesIO
from typing import Generator

log = logging.getLogger(__name__)

# XML files inside GPO Preferences that may hold GPP cpassword values
_GPP_CREDENTIAL_FILENAMES: frozenset[str] = frozenset({
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "Scheduledtasks.xml",
    "DataSources.xml",
    "Printers.xml",
    "Drives.xml",
})

# Script extensions to scan for embedded credentials
_SCRIPT_EXTENSIONS: frozenset[str] = frozenset({".vbs", ".bat", ".cmd", ".ps1"})

# Regex patterns for cleartext credentials in scripts
_SCRIPT_CRED_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?i)password\s*[=:]\s*["\']?([^\s"\'&;]{4,})', re.IGNORECASE),
    re.compile(r'(?i)net\s+use\s+.*?/user:\S+\s+(\S+)', re.IGNORECASE),
    re.compile(r'(?i)runas\s+/user:\S+\s+(\S+)', re.IGNORECASE),
]


class SMBClient:
    """Wraps an impacket SMBConnection with higher-level file-system operations."""

    def __init__(self, smb_conn) -> None:
        self._smb = smb_conn

    # ── low-level helpers ─────────────────────────────────────────────────────

    def list_path(self, share: str, path: str) -> list:
        """List entries under path in share.  Returns empty list on failure."""
        try:
            return self._smb.listPath(share, path.rstrip("\\") + "\\*")
        except Exception as exc:
            log.debug("SMB listPath %s\\%s: %s", share, path, exc)
            return []

    def read_file(self, share: str, path: str) -> bytes | None:
        """Read a file from a share into memory.  Returns None on failure."""
        buf = BytesIO()
        try:
            self._smb.getFile(share, path, buf.write)
            return buf.getvalue()
        except Exception as exc:
            log.debug("SMB getFile %s\\%s: %s", share, path, exc)
            return None

    def shares(self) -> list[dict]:
        """Return available shares as ``{name, comment}`` dicts."""
        try:
            result = []
            for info in self._smb.listShares():
                name = info["shi1_netname"]
                if isinstance(name, bytes):
                    name = name.decode("utf-16-le", errors="replace")
                name = name.rstrip("\x00")
                comment = info.get("shi1_remark", b"")
                if isinstance(comment, bytes):
                    comment = comment.decode("utf-16-le", errors="replace")
                comment = comment.rstrip("\x00")
                result.append({"name": name, "comment": comment})
            return result
        except Exception as exc:
            log.debug("SMB listShares: %s", exc)
            return []

    # ── directory traversal ───────────────────────────────────────────────────

    def iter_directory(
        self,
        share: str,
        path: str,
        *,
        recursive: bool = False,
        max_depth: int = 8,
        _depth: int = 0,
    ) -> Generator[str, None, None]:
        """Yield all non-directory file paths under path (optionally recursive)."""
        if _depth > max_depth:
            return
        for entry in self.list_path(share, path):
            name = entry.get_longname()
            if name in (".", ".."):
                continue
            full_path = f"{path}\\{name}"
            if entry.is_directory():
                if recursive:
                    yield from self.iter_directory(
                        share, full_path, recursive=True, max_depth=max_depth, _depth=_depth + 1
                    )
            else:
                yield full_path

    # ── SYSVOL helpers ────────────────────────────────────────────────────────

    def iter_gpo_credential_files(
        self, domain: str
    ) -> Generator[tuple[str, str, bytes], None, None]:
        """Yield ``(gpo_guid, smb_path, content)`` for GPP and script files in SYSVOL.

        Scans ``SYSVOL\\<domain>\\Policies\\`` for files that commonly contain
        cleartext or encrypted credentials (GPP XML and logon scripts).
        """
        policies_path = f"\\{domain}\\Policies"
        gpos = self.list_path("SYSVOL", policies_path)
        if not gpos:
            log.debug("No GPO objects found under SYSVOL\\%s\\Policies", domain)
            return

        for gpo in gpos:
            gpo_name = gpo.get_longname()
            if gpo_name in (".", "..") or not gpo.is_directory():
                continue
            gpo_path = f"{policies_path}\\{gpo_name}"

            for file_path in self.iter_directory("SYSVOL", gpo_path, recursive=True):
                filename = file_path.rsplit("\\", 1)[-1]
                ext = ("." + filename.rsplit(".", 1)[1].lower()) if "." in filename else ""

                if filename in _GPP_CREDENTIAL_FILENAMES or ext in _SCRIPT_EXTENSIONS:
                    content = self.read_file("SYSVOL", file_path)
                    if content:
                        yield gpo_name, file_path, content

    def read_sysvol_script(self, domain: str, relative_path: str) -> bytes | None:
        """Read a script file from SYSVOL\\<domain>\\scripts\\."""
        path = f"\\{domain}\\scripts\\{relative_path.lstrip('\\/')}"
        return self.read_file("SYSVOL", path)
