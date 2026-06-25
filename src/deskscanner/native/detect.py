"""Platform router — inspect a target and decide which engine should run.

Routing rules (in order), reported with the artifact that matched so the report
can state *why* an engine was chosen:

  1. ``Contents/Resources/app.asar`` (or a discoverable ``app.asar``) -> electron
  2. ``Contents/Frameworks/FlutterMacOS.framework``                  -> flutter
  3. otherwise a valid ``.app`` bundle (has ``Contents/Info.plist``) -> native
  4. nothing recognisable                                            -> unknown
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

ENGINES = ("electron", "flutter", "native")


@dataclass(frozen=True)
class EngineDetection:
    engine: str          # "electron" | "flutter" | "native" | "unknown"
    reason: str          # human-readable explanation
    artifact: str        # the path/artifact the decision matched on
    app_path: str        # normalised bundle path


def _exists(*parts: str) -> Optional[str]:
    p = os.path.join(*parts)
    return p if os.path.exists(p) else None


def _looks_like_js_bundle(directory: str) -> bool:
    """True if a directory contains package.json or readable JS within a few
    levels — mirrors the Electron engine's unpacked-app heuristic."""
    for root, _dirs, files in os.walk(directory):
        for f in files:
            if f == "package.json" or f.endswith((".js", ".mjs", ".cjs")):
                return True
        if root.count(os.sep) - directory.count(os.sep) > 4:
            del _dirs[:]
    return False


def _find_asar(app_path: str) -> Optional[str]:
    """Return an app.asar path if this looks like an Electron bundle."""
    for rel in ("Contents/Resources/app.asar", "resources/app.asar", "app.asar"):
        hit = _exists(app_path, *rel.split("/"))
        if hit:
            return hit
    return None


def detect_engine(target: str, *, override: Optional[str] = None) -> EngineDetection:
    """Decide which engine should scan ``target``.

    ``override`` (from ``--engine``) forces the choice but the reason records it.
    """
    norm = os.path.abspath(os.path.expanduser(target))

    if override:
        if override not in ENGINES:
            raise ValueError(f"unknown engine {override!r}; expected one of {ENGINES}")
        return EngineDetection(override, f"forced by --engine {override}",
                               "<override>", norm)

    if not os.path.exists(norm):
        return EngineDetection("unknown", f"path does not exist: {norm}", "", norm)

    # A bare app.asar file -> electron.
    if os.path.isfile(norm) and norm.endswith(".asar"):
        return EngineDetection("electron", "target is an app.asar archive", norm, norm)

    if os.path.isfile(norm):
        return EngineDetection("unknown",
                               "target is a file, not an app bundle or app.asar",
                               norm, norm)

    # Directory / .app bundle.
    asar = _find_asar(norm)
    if asar:
        return EngineDetection("electron", "found an Electron app.asar", asar, norm)

    flutter = _exists(norm, "Contents", "Frameworks", "FlutterMacOS.framework")
    if flutter:
        return EngineDetection(
            "flutter", "found Contents/Frameworks/FlutterMacOS.framework",
            flutter, norm)

    # Unpacked Electron app: a directory with a readable JS bundle but no asar
    # (the Electron engine's locate() handles these). Checked AFTER flutter so a
    # Flutter app can never be misrouted here.
    for cand in (norm, os.path.join(norm, "Contents", "Resources", "app"),
                 os.path.join(norm, "resources", "app")):
        if os.path.isdir(cand) and _looks_like_js_bundle(cand):
            return EngineDetection(
                "electron", "found a readable JavaScript bundle (unpacked Electron app)",
                cand, norm)

    info = _exists(norm, "Contents", "Info.plist")
    macos_dir = _exists(norm, "Contents", "MacOS")
    if info or macos_dir:
        return EngineDetection(
            "native", "valid .app bundle (Contents/Info.plist) with no asar and "
                      "no FlutterMacOS.framework",
            info or macos_dir, norm)

    return EngineDetection(
        "unknown",
        "no app.asar, no FlutterMacOS.framework, and no Contents/Info.plist — "
        "not a recognised desktop app bundle",
        "", norm)
