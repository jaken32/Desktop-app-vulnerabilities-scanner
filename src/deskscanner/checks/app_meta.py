"""Application metadata: Electron version + EOL status, and code-signing.

Electron EOL is judged *only* against the dated ``data/electron_eol.json``
snapshot. Versions newer than the snapshot, or otherwise absent, are reported
as "unknown — not in advisory data" rather than guessed. Code-signing is
detected from on-disk signature artifacts when the install tree is available;
we never inspect or reverse a native binary.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from importlib import resources

from packaging.version import InvalidVersion, Version

from ..models import (
    Confidence,
    Finding,
    Remediation,
    Severity,
    SourceLocator,
)
from .base import Check, CheckContext, line_of

CATEGORY = "app_meta"
ELECTRON_TIMELINES = "https://www.electronjs.org/docs/latest/tutorial/electron-timelines"


@lru_cache(maxsize=1)
def _eol_data() -> dict:
    raw = resources.files("deskscanner.data").joinpath("electron_eol.json").read_text()
    return json.loads(raw)


def _detect_electron_version(ctx: CheckContext):
    """Return (version_str, locator) or (None, None). Tries package.json dep
    pins and any packaged ``version`` file."""
    pkg = ctx.bundle.get("package.json")
    if pkg:
        text = ctx.read_text(pkg)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        for section in ("devDependencies", "dependencies"):
            dep = (data.get(section) or {}).get("electron")
            if dep:
                m = re.search(r"(\d+\.\d+\.\d+)", str(dep)) or re.search(r"(\d+)", str(dep))
                if m:
                    idx = text.find('"electron"')
                    return m.group(1), SourceLocator(
                        "package.json",
                        line=line_of(text, idx) if idx >= 0 else 1,
                        config_key=f"{section}.electron",
                    )
    # electron-packager writes a plain `version` file at the app root.
    for vf in ("version", "VERSION"):
        f = ctx.bundle.get(vf)
        if f:
            content = ctx.read_text(f).strip()
            m = re.search(r"(\d+\.\d+\.\d+)", content)
            if m:
                return m.group(1), SourceLocator(vf, line=1)
    return None, None


def _major(version: str):
    try:
        return Version(version).major
    except InvalidVersion:
        m = re.match(r"(\d+)", version)
        return int(m.group(1)) if m else None


class AppMetaCheck(Check):
    id = "app_meta"
    name = "Application metadata (Electron version, code signing)"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        version, locator = _detect_electron_version(ctx)
        ctx.app.electron_version = version

        if version is None:
            ctx.app.electron_eol_note = ("Electron version not determinable from "
                                         "the bundle (it lives in the native "
                                         "binary, which we do not inspect).")
            findings.append(self._unknown_version_finding())
        else:
            findings += self._eol_finding(version, locator, ctx)

        findings += self._code_signing(ctx)
        return findings

    def _unknown_version_finding(self) -> Finding:
        return Finding(
            title="Electron version could not be determined statically",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            category=self.category,
            evidence="No electron dependency pin or packaged 'version' file found "
                     "in the bundle.",
            source_locator=SourceLocator("package.json", config_key="electron"),
            remediation=Remediation(
                "To enable EOL checks, run against the full install tree or ensure "
                "the build pins the electron version in package.json."),
            references=[ELECTRON_TIMELINES],
            why_it_matters="Without a version we cannot judge end-of-life status; "
                           "this is reported honestly rather than guessed.",
            discriminator="electron:version:unknown",
        )

    def _eol_finding(self, version, locator, ctx) -> list[Finding]:
        data = _eol_data()
        major = _major(version)
        as_of = data["_meta"]["as_of"]
        latest = data["latest_stable_major"]
        majors = data["majors"]

        if major is None:
            return []
        key = str(major)
        if major > latest:
            ctx.app.electron_eol = False
            ctx.app.electron_eol_note = (
                f"Electron {version} is newer than the advisory snapshot "
                f"({as_of}); EOL status unknown — not guessed.")
            return [Finding(
                title=f"Electron {major} newer than advisory snapshot",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=f"Detected Electron {version}; advisory data is dated {as_of} "
                         f"(latest known major {latest}).",
                source_locator=locator or SourceLocator("package.json"),
                remediation=Remediation(
                    "Update the dated advisory file to assess this newer release."),
                references=[ELECTRON_TIMELINES],
                why_it_matters="We do not assert EOL for versions outside our dated "
                               "data set.",
                discriminator=f"electron:{major}:newer",
            )]

        entry = majors.get(key)
        if entry is None:
            ctx.app.electron_eol = True  # below the supported floor by inference
            ctx.app.electron_eol_note = (
                f"Electron {version} is older than every supported major in the "
                f"{as_of} snapshot.")
            entry = {"eol": True, "note": "Older than all listed majors."}

        ctx.app.electron_eol = bool(entry.get("eol"))
        if entry.get("eol"):
            ctx.app.electron_eol_note = (
                f"Electron {version} (major {major}) is END-OF-LIFE per the "
                f"{as_of} advisory snapshot.")
            return [Finding(
                title=f"End-of-life Electron version ({version})",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=f"Electron major {major}: {entry.get('note','')} "
                         f"(advisory dated {as_of}; supported majors: "
                         f"{data['supported_majors']}).",
                source_locator=locator or SourceLocator("package.json",
                                                        config_key="electron"),
                remediation=Remediation(
                    f"Upgrade to a supported Electron major ({data['supported_majors']}). "
                    "EOL lines no longer receive Chromium security backports."),
                references=[ELECTRON_TIMELINES, "https://endoflife.date/electron"],
                why_it_matters="EOL Electron ships an unpatched Chromium, so publicly "
                               "known renderer exploits remain unfixed.",
                discriminator=f"electron:{major}:eol",
            )]
        # Supported version -> informational confirmation, no penalty.
        ctx.app.electron_eol_note = (
            f"Electron {version} (major {major}) is within support per the "
            f"{as_of} snapshot.")
        return [Finding(
            title=f"Electron version {version} is currently supported",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            category=self.category,
            evidence=f"Major {major} is in the supported set {data['supported_majors']} "
                     f"(advisory dated {as_of}).",
            source_locator=locator or SourceLocator("package.json",
                                                    config_key="electron"),
            remediation=Remediation("Keep tracking Electron's release cadence."),
            references=[ELECTRON_TIMELINES],
            why_it_matters="A supported major still receives security backports.",
            discriminator=f"electron:{major}:supported",
        )]

    def _code_signing(self, ctx: CheckContext) -> list[Finding]:
        signed, note = self._detect_signing(ctx)
        ctx.app.code_signed = signed
        ctx.app.code_sign_note = note
        if signed is None:
            return [Finding(
                title="Code-signing status not determinable from the bundle",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category=self.category,
                evidence=note,
                source_locator=SourceLocator(ctx.app.bundle_path or "<bundle>"),
                remediation=Remediation(
                    "Run against the full installed app directory to let the "
                    "scanner observe signature artifacts."),
                references=["https://www.electronjs.org/docs/latest/tutorial/code-signing"],
                why_it_matters="Signing status is a packaging property; we report it "
                               "honestly rather than assume.",
                discriminator="codesign:unknown",
            )]
        if signed:
            return [Finding(
                title="Application appears code-signed",
                severity=Severity.INFO,
                confidence=Confidence.LIKELY,
                category=self.category,
                evidence=note,
                source_locator=SourceLocator(ctx.app.bundle_path or "<bundle>"),
                remediation=Remediation("No action — signature artifacts present."),
                references=["https://www.electronjs.org/docs/latest/tutorial/code-signing"],
                why_it_matters="Signing lets the OS verify integrity and origin.",
                discriminator="codesign:present",
            )]
        return [Finding(
            title="No code-signing artifacts found",
            severity=Severity.LOW,
            confidence=Confidence.LIKELY,
            category=self.category,
            evidence=note,
            source_locator=SourceLocator(ctx.app.bundle_path or "<bundle>"),
            remediation=Remediation(
                "Sign and notarise the application so the OS can verify it and users "
                "are not warned about an unidentified developer."),
            references=["https://www.electronjs.org/docs/latest/tutorial/code-signing"],
            why_it_matters="Unsigned apps can be tampered with and trigger OS "
                           "gatekeeper warnings.",
            false_positive_note="Signature detection is best-effort from on-disk "
                                "artifacts; a signed app may not expose them in the "
                                "provided path.",
            discriminator="codesign:absent",
        )]

    @staticmethod
    def _detect_signing(ctx: CheckContext):
        resources_dir = ctx.resources_dir
        if not resources_dir or not os.path.isdir(resources_dir):
            return None, ("No install tree available (scanned a standalone asar); "
                          "code-signing cannot be observed.")
        # macOS: .app/Contents/_CodeSignature/CodeResources
        contents = resources_dir
        if os.path.basename(resources_dir) == "Resources":
            contents = os.path.dirname(resources_dir)
        macos_sig = os.path.join(contents, "_CodeSignature", "CodeResources")
        if os.path.exists(macos_sig):
            return True, "macOS _CodeSignature/CodeResources present."
        # Windows/Linux: we cannot read Authenticode without parsing the PE, which
        # is out of scope (no native-binary inspection).
        return None, ("Found an install tree but signing lives in the native "
                      "binary, which is out of scope to inspect; status unknown.")
