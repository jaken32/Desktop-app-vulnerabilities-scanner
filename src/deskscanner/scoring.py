"""Grading: severity × confidence, with diminishing returns.

The score starts at 100 and is reduced by a *penalty* built from the findings.
Each finding's base penalty is ``severity.weight × confidence.weight`` (Info =
0). Penalties are combined with a decay so that the single worst issue counts
in full and each additional one counts a little less — the report reads like a
careful analyst, not a linter screaming CRITICAL at everything. Because the
confidence weight multiplies in, a "possible" finding can never dominate the
grade the way a "confirmed" one can.

The exact bands and weights here mirror the README rubric and are applied
identically to every app.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, ScanResult, Severity

# Tunables — documented in the README so the grade is reproducible & explained.
_PENALTY_SCALE = 5.0
_DECAY = 0.75

_GRADE_BANDS = [
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
    (0.0, "F"),
]


@dataclass
class Score:
    grade: str
    value: float            # 0..100
    rollup: dict            # severity.value -> count (non-info + info separately)
    confidence_note: str


def _base_penalty(f: Finding) -> float:
    return f.severity.weight * f.confidence.weight


def compute_score(findings: list[Finding], minified_ratio: float = 0.0) -> Score:
    scoring_findings = [f for f in findings if f.severity is not Severity.INFO]
    penalties = sorted((_base_penalty(f) for f in scoring_findings), reverse=True)

    combined = 0.0
    for i, p in enumerate(penalties):
        combined += p * (_DECAY ** i)
    value = max(0.0, min(100.0, 100.0 - _PENALTY_SCALE * combined))
    value = round(value, 1)

    grade = next(letter for threshold, letter in _GRADE_BANDS if value >= threshold)

    rollup: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        rollup[f.severity.value] += 1

    confidence_note = _confidence_note(minified_ratio, findings)
    return Score(grade=grade, value=value, rollup=rollup, confidence_note=confidence_note)


def _confidence_note(minified_ratio: float, findings: list[Finding]) -> str:
    parts = []
    if minified_ratio >= 0.6:
        parts.append("reduced — the bundle is largely minified/packed, so some "
                     "findings carry lower confidence and clean areas may be "
                     "under-reported")
    elif minified_ratio >= 0.25:
        parts.append("partially reduced — some bundle files are minified")
    else:
        parts.append("normal — bundle was largely readable")
    n_possible = sum(1 for f in findings if f.confidence.value == "possible")
    if n_possible:
        parts.append(f"{n_possible} finding(s) are low-confidence ('possible') and "
                     "are weighted down in the grade")
    return "; ".join(parts)


def apply_score(result: ScanResult) -> ScanResult:
    score = compute_score(result.findings, result.app.minified_ratio)
    result.grade = score.grade
    result.score = score.value
    result.confidence_note = score.confidence_note
    return result


def _efficiency_note(result: ScanResult) -> str:
    parts = []
    summ = result.size_summary or {}
    if summ.get("total_human"):
        parts.append(f"footprint {summ['total_human']} across "
                     f"{summ.get('file_count', 0)} files")
    n_possible = sum(1 for f in result.efficiency_findings
                     if f.confidence.value == "possible")
    if n_possible:
        parts.append(f"{n_possible} optimization(s) are judgement calls "
                     "('possible') and weighted down in the grade")
    parts.append("static size analysis only — no runtime profiling")
    return "; ".join(parts)


def apply_efficiency_score(result: ScanResult) -> ScanResult:
    """Grade the efficiency axis from its own findings (same severity×confidence
    decay math as security), kept entirely separate from the security grade."""
    score = compute_score(result.efficiency_findings, result.app.minified_ratio)
    result.efficiency_grade = score.grade
    result.efficiency_score = score.value
    result.efficiency_note = _efficiency_note(result)
    return result


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Deterministic ordering: severity, then confidence, then stable id.

    Volatile (live-probe) findings sort *after* equivalent static ones so the
    static, reproducible part of the report comes first."""
    return sorted(
        findings,
        key=lambda f: (
            f.severity.rank,
            f.confidence.rank,
            f.volatile,
            f.category,
            f.stable_id,
        ),
    )
