"""Dependency analysis — strictly NO-FABRICATION.

Two honest modes only:
  1. "Outdated major version" — derived purely by comparing the resolved
     version's major against a DATED ``latest_major`` snapshot we ship. This is
     verifiable from version numbers alone.
  2. Named advisories — emitted ONLY for entries present in the dated
     ``dependency_advisories.json`` 'advisories' list, each with a citation.

Anything not covered is reported as "not scanned for known CVEs". We never
invent a CVE, advisory, or version-specific vulnerability from memory.
"""

from __future__ import annotations

import json
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

CATEGORY = "dependencies"


@lru_cache(maxsize=1)
def _advisory_data() -> dict:
    raw = resources.files("deskscanner.data").joinpath(
        "dependency_advisories.json").read_text()
    return json.loads(raw)


def _clean_version(spec: str):
    """Best-effort exact version from a resolved lock entry or a pin.
    Returns a packaging.Version or None. Range specs (^,~,>=) are treated as
    'not a fixed version' for major comparison unless they pin a concrete base.
    """
    if not spec:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", spec)
    if not m:
        m2 = re.match(r"\D*(\d+)", spec)
        if m2:
            try:
                return Version(m2.group(1))
            except InvalidVersion:
                return None
        return None
    try:
        return Version(".".join(m.groups()))
    except InvalidVersion:
        return None


def _parse_lock_versions(ctx: CheckContext) -> dict:
    """Map package-name -> resolved version string from a lockfile, if present."""
    versions: dict[str, str] = {}
    lock = ctx.bundle.get("package-lock.json")
    if lock:
        try:
            data = json.loads(ctx.read_text(lock))
        except json.JSONDecodeError:
            data = {}
        # npm v7+ "packages" keyed by node_modules path.
        for path, meta in (data.get("packages") or {}).items():
            if not path:
                continue
            name = path.split("node_modules/")[-1]
            if isinstance(meta, dict) and meta.get("version"):
                versions[name] = meta["version"]
        # npm v6 "dependencies".
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                versions.setdefault(name, meta["version"])
    yarn = ctx.bundle.get("yarn.lock")
    if yarn:
        text = ctx.read_text(yarn)
        # yarn.lock blocks: `name@range:\n  version "1.2.3"`
        for block in re.finditer(
            r'^"?([^@\n"][^@\n]*)@[^\n]*:\n(?:.*\n)*?\s+version\s+"([^"]+)"',
            text, re.MULTILINE,
        ):
            versions.setdefault(block.group(1), block.group(2))
    return versions


class DependenciesCheck(Check):
    id = "dependencies"
    name = "Dependency hygiene (outdated majors + dated advisories)"
    category = CATEGORY

    def run(self, ctx: CheckContext) -> list[Finding]:
        pkg = ctx.bundle.get("package.json")
        if not pkg:
            return []
        text = ctx.read_text(pkg)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return [self._scope_note(0)]

        declared: dict[str, str] = {}
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                declared.setdefault(name, str(spec))

        lock_versions = _parse_lock_versions(ctx)
        advisory = _advisory_data()
        latest_major = advisory["latest_major"]
        as_of = advisory["_meta"]["as_of"]

        findings: list[Finding] = []
        for name, spec in sorted(declared.items()):
            resolved = lock_versions.get(name, spec)
            version = _clean_version(resolved)
            findings += self._outdated_major(ctx, text, name, spec, version,
                                              latest_major, as_of)

        findings += self._named_advisories(ctx, text, declared, lock_versions,
                                            advisory)
        findings.append(self._scope_note(len(advisory.get("advisories", []))))
        return findings

    def _outdated_major(self, ctx, text, name, spec, version, latest_major, as_of):
        if version is None or name not in latest_major:
            return []
        current = latest_major[name]
        behind = current - version.major
        if behind <= 0:
            return []
        idx = text.find(f'"{name}"')
        line = line_of(text, idx) if idx >= 0 else 1
        # Severity scales with how far behind; confidence is LIKELY because a
        # major pin can be deliberate (vendored, patched fork, etc.).
        severity = Severity.MEDIUM if behind >= 3 else Severity.LOW
        return [Finding(
            title=f"Outdated major version: {name} {version} (latest major {current})",
            severity=severity,
            confidence=Confidence.LIKELY,
            category=self.category,
            evidence=f"Declared/resolved {name}@{version} vs latest major {current} "
                     f"(snapshot {as_of}); {behind} major version(s) behind.",
            source_locator=SourceLocator("package.json", line=line, config_key=name),
            remediation=Remediation(
                f"Review {name}'s changelog and upgrade toward major {current}, "
                "testing for breaking changes."),
            references=["https://github.com/advisories",
                        "https://docs.npmjs.com/cli/v10/commands/npm-outdated"],
            why_it_matters="Several majors behind usually means missed security "
                           "fixes; this is derived from version numbers only, not a "
                           "specific CVE claim.",
            false_positive_note="A pinned older major can be intentional (a patched "
                                "fork or compatibility constraint). This is not a "
                                "CVE assertion.",
            discriminator=f"dep:{name}:outdated-major",
        )]

    def _named_advisories(self, ctx, text, declared, lock_versions, advisory):
        out: list[Finding] = []
        for adv in advisory.get("advisories", []):
            name = adv.get("package")
            if name not in declared and name not in lock_versions:
                continue
            resolved = lock_versions.get(name, declared.get(name, ""))
            version = _clean_version(resolved)
            if version is None:
                continue
            if not _version_in_range(version, adv.get("vulnerable_range", "")):
                continue
            idx = text.find(f'"{name}"')
            line = line_of(text, idx) if idx >= 0 else 1
            out.append(Finding(
                title=f"{adv.get('id', 'advisory')}: {name} {version}",
                severity=Severity(adv.get("severity", "medium")),
                confidence=Confidence.LIKELY,
                category=self.category,
                evidence=f"{name}@{version} matches {adv.get('id')} "
                         f"(range {adv.get('vulnerable_range')}). "
                         f"Advisory dated {advisory['_meta']['as_of']}.",
                source_locator=SourceLocator("package.json", line=line, config_key=name),
                remediation=Remediation(
                    adv.get("remediation", f"Upgrade {name} to a fixed version.")),
                references=adv.get("references", []),
                why_it_matters=adv.get("summary", "Listed in the dated advisory file."),
                discriminator=f"dep:{name}:{adv.get('id')}",
            ))
        return out

    def _scope_note(self, advisory_count: int) -> Finding:
        return Finding(
            title="CVE matching scope (no-fabrication policy)",
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            category=self.category,
            evidence=f"CVE/advisory matching used only the dated advisory file "
                     f"({advisory_count} entr{'y' if advisory_count == 1 else 'ies'}). "
                     "Packages not covered are 'not scanned for known CVEs'. No CVE "
                     "is ever asserted from model memory.",
            source_locator=SourceLocator("deskscanner/data/dependency_advisories.json"),
            remediation=Remediation(
                "Wire in a real advisory feed (e.g. OSV, GitHub Advisory DB) and add "
                "dated entries to enable full CVE matching."),
            references=["https://osv.dev", "https://github.com/advisories"],
            why_it_matters="Honest scoping: outdated-major findings come from version "
                           "numbers; CVE matching is limited to the dated file.",
            discriminator="dep:cve-scope",
        )


def _version_in_range(version: Version, spec: str) -> bool:
    """Tiny range evaluator for advisory specs like '<1.2.3' or '>=1.0.0 <1.4.5'."""
    if not spec:
        return False
    ok = True
    for part in spec.split():
        m = re.match(r"(<=|>=|<|>|==)?\s*(\d+\.\d+\.\d+)", part.strip())
        if not m:
            continue
        op = m.group(1) or "=="
        try:
            bound = Version(m.group(2))
        except InvalidVersion:
            continue
        ok = ok and {
            "<": version < bound,
            "<=": version <= bound,
            ">": version > bound,
            ">=": version >= bound,
            "==": version == bound,
        }[op]
    return ok
