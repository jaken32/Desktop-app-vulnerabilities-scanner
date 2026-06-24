"""Core data models for deskscanner.

Everything the engine produces flows through these immutable-ish dataclasses.
The shapes here are deliberately stable: ``Finding`` is the contract every
check module must emit, and ``stable_id`` is what determinism and diffing rely
on.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Severity(enum.Enum):
    """How bad the issue is *if real*. Ordered worst-first by ``weight``.

    The exact bands below are the hardcoded rubric (see README). They are
    applied identically to every scanned app.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            "critical": 10.0,
            "high": 6.0,
            "medium": 3.0,
            "low": 1.0,
            "info": 0.0,
        }[self.value]

    @property
    def rank(self) -> int:
        """Sort rank; lower = more severe."""
        return ["critical", "high", "medium", "low", "info"].index(self.value)

    @property
    def label(self) -> str:
        return self.value.capitalize()

    # Colorblind-safe glyph paired with the colour so severity is never
    # communicated by colour alone (used by both CLI and HTML reports).
    @property
    def glyph(self) -> str:
        return {
            "critical": "✖",
            "high": "▲",
            "medium": "●",
            "low": "○",
            "info": "·",
        }[self.value]


class Confidence(enum.Enum):
    """How sure we are the finding is real and active — *separate* from severity.

    confirmed  the insecure setting is unambiguously present and active.
    likely     strong evidence, but a mitigation could exist elsewhere.
    possible   pattern present but plausibly intentional / a false positive.
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"

    @property
    def weight(self) -> float:
        # Multiplies severity weight when scoring. Low-confidence findings
        # must not dominate the grade, hence the steep drop-off.
        return {"confirmed": 1.0, "likely": 0.6, "possible": 0.3}[self.value]

    @property
    def rank(self) -> int:
        return ["confirmed", "likely", "possible"].index(self.value)

    @property
    def label(self) -> str:
        return self.value.capitalize()


@dataclass(frozen=True)
class SourceLocator:
    """Points a reader at the exact evidence so they can verify it themselves.

    Exactly one of ``line`` / ``config_key`` should normally be set, but both
    are allowed. ``path`` is relative to the bundle root (or a synthetic label
    like ``<local-api>`` for probe findings).
    """

    path: str
    line: Optional[int] = None
    config_key: Optional[str] = None

    def render(self) -> str:
        out = self.path
        if self.line is not None:
            out += f":{self.line}"
        if self.config_key:
            out += f" [{self.config_key}]"
        return out


@dataclass(frozen=True)
class Remediation:
    """Concrete fix guidance. ``code`` is an optional snippet shown verbatim."""

    summary: str
    code: Optional[str] = None


@dataclass
class Finding:
    """The fixed-shape unit every check emits.

    ``stable_id`` is derived from the *non-volatile* identity of a finding so
    that the same bundle always produces the same id (determinism + diff).
    """

    title: str
    severity: Severity
    confidence: Confidence
    category: str
    evidence: str
    source_locator: SourceLocator
    remediation: Remediation
    references: list[str] = field(default_factory=list)
    why_it_matters: str = ""
    false_positive_note: Optional[str] = None
    # A short, check-defined discriminator that distinguishes findings of the
    # same kind from one another (e.g. the window label, the dep name). Folded
    # into the stable id. NOT volatile.
    discriminator: str = ""
    # True for findings derived from the LIVE local-API probe. These are
    # excluded from diffs (their presence/values depend on whether the service
    # happened to be running), though they still appear in the report.
    volatile: bool = False

    @property
    def stable_id(self) -> str:
        """Deterministic id. Excludes volatile fields (timestamps, live probe
        values). Built from category + a normalised title + locator +
        discriminator."""
        basis = "|".join(
            [
                self.category,
                self.severity.value,
                self.title.strip().lower(),
                self.source_locator.path,
                str(self.source_locator.line or ""),
                self.source_locator.config_key or "",
                self.discriminator,
            ]
        )
        digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]
        return f"DS-{digest}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "evidence": self.evidence,
            "source_locator": {
                "path": self.source_locator.path,
                "line": self.source_locator.line,
                "config_key": self.source_locator.config_key,
                "rendered": self.source_locator.render(),
            },
            "remediation": asdict(self.remediation),
            "references": list(self.references),
            "why_it_matters": self.why_it_matters,
            "false_positive_note": self.false_positive_note,
            "volatile": self.volatile,
        }


@dataclass
class AppInfo:
    """Metadata about the scanned target."""

    name: str = "Unknown"
    version: str = "unknown"
    electron_version: Optional[str] = None
    electron_eol: Optional[bool] = None
    electron_eol_note: Optional[str] = None
    code_signed: Optional[bool] = None
    code_sign_note: str = ""
    bundle_path: str = ""
    is_electron: bool = True
    minified_ratio: float = 0.0  # 0..1 share of scanned JS that looks minified

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything a single scan produced. Serialisable to JSON for diffing."""

    app: AppInfo
    findings: list[Finding] = field(default_factory=list)
    # Volatile — excluded from stable ids and diffs.
    scan_timestamp: Optional[str] = None
    probe_attempted: bool = False
    probe_reachable: bool = False
    notes: list[str] = field(default_factory=list)
    grade: str = "N/A"
    score: float = 0.0
    confidence_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "deskscanner/1",
            "app": self.app.to_dict(),
            "scan_timestamp": self.scan_timestamp,
            "probe_attempted": self.probe_attempted,
            "probe_reachable": self.probe_reachable,
            "grade": self.grade,
            "score": self.score,
            "confidence_note": self.confidence_note,
            "notes": list(self.notes),
            "findings": [f.to_dict() for f in self.findings],
        }


def severity_from_str(value: str) -> Severity:
    return Severity(value)


def confidence_from_str(value: str) -> Confidence:
    return Confidence(value)
