"""Check base class, shared scan context, and text-analysis helpers.

A *check* is a pluggable module that inspects the bundle (and, for the local
API, a loopback service) and emits zero or more :class:`Finding` objects. The
engine discovers checks via the registry in ``checks/__init__.py`` and runs
them in a fixed order so output is deterministic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..models import AppInfo, Finding
from ..unpack import Bundle, BundleFile


# Heuristics for "is this file minified / packed / obfuscated?" — when true we
# can still pattern-match but must LOWER confidence and never claim a clean
# bill on code we couldn't meaningfully read.
def is_minified(text: str, relpath: str = "") -> bool:
    if relpath.endswith(".min.js"):
        return True
    if not text:
        return False
    lines = text.split("\n")
    # Long average line length is the classic minification tell.
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return False
    avg_len = sum(len(ln) for ln in non_empty) / len(non_empty)
    longest = max(len(ln) for ln in non_empty)
    # webpack/terser output: very long lines, few of them.
    if longest > 2000 or (avg_len > 250 and len(non_empty) < max(1, len(text) // 200)):
        return True
    # Dense single-line bundles.
    if len(non_empty) <= 3 and len(text) > 1000:
        return True
    return False


def line_of(text: str, index: int) -> int:
    """1-based line number for a character ``index`` into ``text``."""
    if index <= 0:
        return 1
    return text.count("\n", 0, index) + 1


def snippet_around(text: str, index: int, length: int, *, width: int = 160) -> str:
    """A single-line evidence snippet around a match, trimmed for display."""
    start = max(0, index - width // 4)
    end = min(len(text), index + length + width // 4)
    frag = text[start:end].replace("\n", "⏎").replace("\r", "")
    if len(frag) > width:
        frag = frag[:width] + "…"
    return frag.strip()


@dataclass
class CheckContext:
    """Everything a check needs. Shared, read-only across checks."""

    bundle: Bundle
    app: AppInfo
    resources_dir: Optional[str] = None
    asar_path: Optional[str] = None
    # Local-API probe controls (the only active behaviour in the tool).
    probe_enabled: bool = False
    probe_timeout: float = 4.0
    # Explicit on-disk data dirs for the storage check (tests/CLI override). When
    # empty, the storage check auto-derives candidates from the app name.
    storage_paths: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    _text_cache: dict = field(default_factory=dict, repr=False)
    _js_cache: list = field(default_factory=list, repr=False)

    def read_text(self, f: BundleFile) -> str:
        if f.relpath not in self._text_cache:
            try:
                self._text_cache[f.relpath] = f.read_text()
            except Exception:  # pragma: no cover - defensive
                self._text_cache[f.relpath] = ""
        return self._text_cache[f.relpath]

    def js_files(self) -> tuple:
        if not self._js_cache:
            self._js_cache.append(tuple(
                f for f in self.bundle.files
                if f.relpath.endswith((".js", ".mjs", ".cjs", ".html"))
            ))
        return self._js_cache[0]

    def file_is_minified(self, f: BundleFile) -> bool:
        return is_minified(self.read_text(f), f.relpath)


class Check:
    """Base class for all checks. Subclasses set the class attrs and implement
    :meth:`run`. ``run`` must be deterministic given the same bundle (the local
    API probe is the only exception and its volatile results are flagged)."""

    id: str = "base"
    name: str = "Base check"
    category: str = "general"

    def run(self, ctx: CheckContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError
