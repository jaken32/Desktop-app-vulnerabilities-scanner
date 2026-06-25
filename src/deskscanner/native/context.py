"""Shared, read-only context for the native engine.

Holds everything the native checks need — parsed Info.plist, entitlements,
codesign/spctl results, framework inventory — plus a path-traversal-safe
filesystem reader confined to the app bundle and the explicit storage roots.
Tool outputs can be injected (tests pass captured strings) so the whole engine
runs deterministically off-macOS.
"""

from __future__ import annotations

import os
import plistlib
from dataclasses import dataclass, field
from typing import Optional

from ..unpack import UnsafePathError
from . import macos

# Hard cap on any single file we read (defence against huge files / OOM).
_MAX_READ = 16 * 1024 * 1024


class SafeFS:
    """Filesystem reader confined to a fixed set of roots.

    Every access is realpath-resolved and verified to stay within a root, so
    ``..`` traversal and symlink escapes are refused (mirrors the asar
    unpacker's guarantee for the native side)."""

    def __init__(self, roots: list[str]):
        self.roots = [os.path.realpath(r) for r in roots if r]

    def resolve(self, path: str) -> str:
        real = os.path.realpath(path)
        for root in self.roots:
            if real == root or real.startswith(root + os.sep):
                return real
        raise UnsafePathError(f"path escapes allowed roots: {path!r}")

    def read_bytes(self, path: str, max_bytes: int = _MAX_READ) -> bytes:
        real = self.resolve(path)
        if os.path.islink(real) or not os.path.isfile(real):
            raise UnsafePathError(f"not a regular file: {path!r}")
        with open(real, "rb") as fp:
            return fp.read(max_bytes)

    def read_text(self, path: str, max_bytes: int = _MAX_READ) -> str:
        return self.read_bytes(path, max_bytes).decode("utf-8", errors="replace")

    def exists(self, path: str) -> bool:
        try:
            self.resolve(path)
        except UnsafePathError:
            return False
        return os.path.exists(path)


@dataclass
class NativeContext:
    app_path: str
    engine: str                      # "flutter" | "native"
    name: str = "Unknown"
    version: str = "unknown"
    info_plist: dict = field(default_factory=dict)
    info_plist_path: str = ""
    entitlements: dict = field(default_factory=dict)
    codesign: dict = field(default_factory=dict)
    spctl: dict = field(default_factory=dict)
    stapled: Optional[bool] = None
    frameworks: list = field(default_factory=list)   # framework dir names
    bundles: list = field(default_factory=list)      # .bundle resource names
    storage_paths: list = field(default_factory=list)
    probe_enabled: bool = False
    prospect: bool = False
    tools_available: bool = True
    notes: list = field(default_factory=list)
    fs: SafeFS = field(default=None)  # type: ignore[assignment]

    @property
    def macos_dir(self) -> str:
        return os.path.join(self.app_path, "Contents", "MacOS")

    @property
    def resources_dir(self) -> str:
        return os.path.join(self.app_path, "Contents", "Resources")

    @property
    def frameworks_dir(self) -> str:
        return os.path.join(self.app_path, "Contents", "Frameworks")


def _read_info_plist(fs: SafeFS, app_path: str) -> tuple:
    path = os.path.join(app_path, "Contents", "Info.plist")
    try:
        raw = fs.read_bytes(path)
    except (UnsafePathError, OSError):
        return {}, ""
    try:
        data = plistlib.loads(raw)
        return (data if isinstance(data, dict) else {}), path
    except Exception:
        return {}, path


def _inventory(app_path: str, subdir: str, suffix: str) -> list:
    root = os.path.join(app_path, "Contents", subdir)
    out = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if name.endswith(suffix) and not os.path.islink(os.path.join(root, name)):
                out.append(name)
    return out


def build_native_context(
    app_path: str,
    *,
    engine: str = "native",
    runner: macos.Runner = macos.default_runner,
    storage_paths: Optional[list] = None,
    probe_enabled: bool = False,
    prospect: bool = False,
    # Test/injection hooks — bypass the real tools with captured output.
    codesign_text: Optional[str] = None,
    entitlements_text: Optional[str] = None,
    spctl_result: Optional[tuple] = None,
    stapler_rc: Optional[int] = None,
    _run_tools: bool = True,
) -> NativeContext:
    app_path = os.path.realpath(os.path.expanduser(app_path))
    roots = [app_path] + [os.path.realpath(os.path.expanduser(p))
                          for p in (storage_paths or [])]
    fs = SafeFS(roots)

    info, info_path = _read_info_plist(fs, app_path)
    name = str(info.get("CFBundleName") or info.get("CFBundleDisplayName")
               or os.path.splitext(os.path.basename(app_path))[0] or "Unknown")
    version = str(info.get("CFBundleShortVersionString")
                  or info.get("CFBundleVersion") or "unknown")

    # Tool outputs: use injected values when provided, else run the real tools.
    if codesign_text is None and _run_tools:
        codesign_text = macos.run_codesign_info(app_path, runner)
    if entitlements_text is None and _run_tools:
        entitlements_text = macos.run_entitlements(app_path, runner)
    if spctl_result is None and _run_tools:
        spctl_result = macos.run_spctl(app_path, runner)
    if stapler_rc is None and _run_tools:
        stapler_rc = macos.run_stapler(app_path, runner)

    codesign = macos.parse_codesign(codesign_text)
    entitlements = macos.parse_entitlements(entitlements_text)
    spctl = macos.parse_spctl(spctl_result)
    stapled = None if stapler_rc is None else (stapler_rc == 0)
    tools_available = codesign.get("available", False) or spctl.get("available", False)

    notes = []
    if not tools_available:
        notes.append("codesign/spctl were not available on this host, so "
                     "signing, notarization, hardened-runtime, sandbox and "
                     "entitlement checks could not be assessed. Run on macOS for "
                     "those results.")

    return NativeContext(
        app_path=app_path,
        engine=engine,
        name=name,
        version=version,
        info_plist=info,
        info_plist_path=info_path,
        entitlements=entitlements,
        codesign=codesign,
        spctl=spctl,
        stapled=stapled,
        frameworks=_inventory(app_path, "Frameworks", ".framework"),
        bundles=_inventory(app_path, "Resources", ".bundle"),
        storage_paths=[os.path.realpath(os.path.expanduser(p))
                       for p in (storage_paths or [])],
        probe_enabled=probe_enabled,
        prospect=prospect,
        tools_available=tools_available,
        notes=notes,
        fs=fs,
    )
