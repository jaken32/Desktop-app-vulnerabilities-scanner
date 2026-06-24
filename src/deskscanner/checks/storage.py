"""Local data-storage checks.

Locates the app's on-disk user-data directory (read-only) and flags two
things: plaintext secrets sitting in config/state files, and world-/group-
readable permissions on sensitive files. We never modify anything, never
follow symlinks, and bound how much we read.

These findings depend on the host filesystem, not the bundle, so they are
naturally excluded from the deterministic-on-the-same-bundle guarantee (a
bundle with no installed data dir simply yields none).
"""

from __future__ import annotations

import os
import stat

from ..models import (
    Confidence,
    Finding,
    Remediation,
    Severity,
    SourceLocator,
)
from .base import Check, CheckContext, line_of
from .secrets import _PROVIDER_PATTERNS, _is_placeholder, _redact

CATEGORY = "storage"
OWASP_STORAGE = "https://owasp.org/www-community/vulnerabilities/Insecure_Storage"

_SENSITIVE_NAMES = (
    "config.json", "settings.json", "preferences", "cookies", "login data",
    "credentials", "token", "secrets", "leveldb", ".env",
)
_TEXT_SUFFIXES = (".json", ".txt", ".env", ".ini", ".cfg", ".yaml", ".yml", ".log")
_MAX_FILE = 2 * 1024 * 1024  # only scan small text files for plaintext secrets
_MAX_FILES = 2000


def _candidate_data_dirs(app_name: str) -> list[str]:
    home = os.path.expanduser("~")
    name = app_name
    candidates = [
        os.path.join(home, ".config", name),
        os.path.join(home, "Library", "Application Support", name),
        os.path.join(os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming")), name),
    ]
    return [c for c in candidates if c and os.path.isdir(c)]


def _is_sensitive(path: str) -> bool:
    low = os.path.basename(path).lower()
    return any(tok in low for tok in _SENSITIVE_NAMES)


class StorageCheck(Check):
    id = "storage"
    name = "Local data storage (plaintext secrets, permissions)"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        dirs = list(getattr(ctx, "storage_paths", []) or [])
        if not dirs:
            dirs = _candidate_data_dirs(ctx.app.name)
        if not dirs:
            ctx.notes.append("No on-disk data directory found for storage checks.")
            return []

        findings: list[Finding] = []
        scanned = 0
        for base in dirs:
            for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
                dirnames[:] = [d for d in dirnames
                               if not os.path.islink(os.path.join(dirpath, d))]
                for fname in filenames:
                    if scanned >= _MAX_FILES:
                        break
                    scanned += 1
                    full = os.path.join(dirpath, fname)
                    if os.path.islink(full):
                        continue
                    rel = os.path.relpath(full, base)
                    findings += self._check_permissions(full, rel)
                    findings += self._check_plaintext(full, rel)
        return findings

    def _check_permissions(self, full: str, rel: str) -> list[Finding]:
        if os.name == "nt":
            return []  # POSIX-mode bits are not meaningful on Windows
        if not _is_sensitive(full):
            return []
        try:
            mode = os.stat(full).st_mode
        except OSError:
            return []
        world_or_group = mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)
        if not world_or_group:
            return []
        return [Finding(
            title="Sensitive data file readable by group/others",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            category=self.category,
            evidence=f"{rel} has mode {stat.filemode(mode)} "
                     f"({oct(stat.S_IMODE(mode))}).",
            source_locator=SourceLocator(rel, config_key="filesystem-permissions"),
            remediation=Remediation(
                "Restrict the file to the owner only.",
                "chmod 600 " + rel),
            references=[OWASP_STORAGE],
            why_it_matters="Other local users can read app credentials/state when "
                           "sensitive files are not owner-only.",
            discriminator=f"storage:perm:{rel}",
        )]

    def _check_plaintext(self, full: str, rel: str) -> list[Finding]:
        if not full.lower().endswith(_TEXT_SUFFIXES):
            return []
        try:
            if os.path.getsize(full) > _MAX_FILE:
                return []
            with open(full, "rb") as fp:
                text = fp.read(_MAX_FILE).decode("utf-8", errors="replace")
        except OSError:
            return []
        out: list[Finding] = []
        for name, severity, pattern, _conf in _PROVIDER_PATTERNS:
            for m in pattern.finditer(text):
                captured = m.group(len(m.groups())) if m.groups() else m.group(0)
                if _is_placeholder(captured):
                    continue
                out.append(Finding(
                    title=f"Plaintext {name} in local data file",
                    severity=severity if severity != Severity.INFO else Severity.HIGH,
                    confidence=Confidence.LIKELY,
                    category=self.category,
                    evidence=f"{name} in {rel}: {_redact(captured)}",
                    source_locator=SourceLocator(rel, line=line_of(text, m.start())),
                    remediation=Remediation(
                        "Store secrets in the OS keychain/credential store, not in "
                        "plaintext under the user-data directory."),
                    references=[OWASP_STORAGE],
                    why_it_matters="Plaintext credentials on disk are recoverable by "
                                   "any process or user with read access.",
                    discriminator=f"storage:secret:{rel}:{name}",
                ))
                break  # one finding per (file, provider) is enough
        return out
