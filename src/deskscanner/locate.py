"""Locate an installed Electron application's bundle on disk.

Given a path the user points us at — an app directory, a ``.app`` bundle, an
``app.asar`` directly, or a platform install root — figure out where the
Electron resources live and return a :class:`Bundle`. If we can't find any
asar or readable JS, we say so plainly; we never fall back to analysing a
native binary.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .unpack import (
    Bundle,
    UnpackError,
    UnpackLimits,
    load_asar,
    load_directory,
)


class TargetNotElectronError(Exception):
    """The target exists but has no asar / no readable JS bundle."""


@dataclass
class Located:
    bundle: Bundle
    resources_dir: Optional[str]
    asar_path: Optional[str]
    app_name_hint: str


# Common relative locations of the resources dir inside an install tree, across
# the three desktop platforms.
_RESOURCE_HINTS = [
    "resources",                                   # win/linux
    "Contents/Resources",                          # macOS .app
    os.path.join("Contents", "Resources"),
]


def _looks_like_js_bundle(directory: str) -> bool:
    for root, _dirs, files in os.walk(directory):
        for f in files:
            if f.endswith((".js", ".mjs", ".cjs")) or f == "package.json":
                return True
        # don't descend forever on huge trees just to answer yes/no
        if root.count(os.sep) - directory.count(os.sep) > 4:
            break
    return False


def _find_resources_dir(path: str) -> Optional[str]:
    for hint in _RESOURCE_HINTS:
        candidate = os.path.join(path, hint)
        if os.path.isdir(candidate):
            return candidate
    # Some Linux installs put app.asar in the same dir.
    if os.path.isdir(path):
        return path
    return None


def locate(target: str, limits: Optional[UnpackLimits] = None) -> Located:
    """Resolve ``target`` to a usable :class:`Bundle`.

    Raises :class:`TargetNotElectronError` with a clear message when the target
    is not an Electron/web-tech app (so callers can stop gracefully).
    """
    limits = limits or UnpackLimits()
    target = os.path.expanduser(target)
    if not os.path.exists(target):
        raise TargetNotElectronError(f"Path does not exist: {target}")

    app_name_hint = os.path.basename(target.rstrip(os.sep)) or target

    # Case 1: pointed straight at an app.asar.
    if os.path.isfile(target) and target.endswith(".asar"):
        try:
            bundle = load_asar(target, limits)
        except UnpackError as exc:
            raise TargetNotElectronError(
                f"'{target}' is not a readable asar archive: {exc}"
            ) from None
        return Located(bundle, os.path.dirname(target), target,
                       _clean_name(app_name_hint))

    if os.path.isfile(target):
        raise TargetNotElectronError(
            f"'{target}' is a file, not an Electron bundle. Point me at the "
            f"installed app directory, a .app bundle, or an app.asar."
        )

    # Case 2: a directory — find the resources dir, then an asar or unpacked app.
    resources = _find_resources_dir(target)
    if resources is None:
        raise TargetNotElectronError(
            f"Could not find a resources directory under {target}."
        )

    asar = os.path.join(resources, "app.asar")
    if os.path.isfile(asar):
        try:
            bundle = load_asar(asar, limits)
        except UnpackError as exc:
            raise TargetNotElectronError(
                f"Found app.asar but could not read it safely: {exc}"
            ) from None
        return Located(bundle, resources, asar, _clean_name(app_name_hint))

    # Case 3: unpacked app directory (resources/app/ with a package.json).
    app_dir = os.path.join(resources, "app")
    if os.path.isdir(app_dir) and _looks_like_js_bundle(app_dir):
        bundle = load_directory(app_dir, limits)
        return Located(bundle, resources, None, _clean_name(app_name_hint))

    # Case 4: the target directory itself is the unpacked bundle.
    if _looks_like_js_bundle(target):
        bundle = load_directory(target, limits)
        return Located(bundle, target, None, _clean_name(app_name_hint))

    raise TargetNotElectronError(
        f"'{target}' has no app.asar and no readable JavaScript bundle. "
        f"It does not look like an Electron application, so there is nothing "
        f"to statically analyse (this tool never reverse-engineers native "
        f"binaries)."
    )


def _clean_name(raw: str) -> str:
    for suffix in (".app", ".exe", ".asar"):
        if raw.lower().endswith(suffix):
            raw = raw[: -len(suffix)]
    return raw or "Unknown"
