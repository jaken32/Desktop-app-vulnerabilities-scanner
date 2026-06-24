"""Dense developer-audit CLI report (Lighthouse/SAST-style, not marketing).

Severity is communicated by glyph + label + colour (never colour alone), so it
remains legible without colour or for colourblind readers. Colour is disabled
automatically when output is not a TTY or ``NO_COLOR`` is set.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from ..diff import DiffResult
from ..models import Confidence, ScanResult, Severity
from . import coverage

_SEV_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
_GRADE_COLOR = {"A": "\033[1;32m", "B": "\033[32m", "C": "\033[33m",
                "D": "\033[33m", "F": "\033[1;31m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


class _Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        if not self.enabled:
            return text
        return f"{code}{text}{_RESET}"


def _color_enabled(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("DESKSCANNER_FORCE_COLOR") == "1":
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def render_cli(result: ScanResult, *, diff: Optional[DiffResult] = None,
               stream=None) -> None:
    stream = stream or sys.stdout
    s = _Style(_color_enabled(stream))
    w = lambda line="": print(line, file=stream)

    w()
    w(s("deskscanner — Electron application analysis report", _BOLD))
    w(s(_mode_subtitle(result), _DIM))
    w("─" * 70)

    if result.ran_security:
        _render_security(w, s, result, diff)
    if result.ran_efficiency:
        _render_efficiency(w, s, result)

    if result.notes:
        w("")
        w(s("  Notes", _BOLD))
        for note in result.notes:
            w(f"    · {note}")
    w("")


def _mode_subtitle(result: ScanResult) -> str:
    return {
        "security": "static analysis + safe loopback inspection",
        "efficiency": "static efficiency / footprint analysis (no runtime profiling)",
        "all": "security + efficiency (two independent grades)",
    }.get(result.mode, "static analysis")


def _render_security(w, s, result: ScanResult,
                     diff: Optional[DiffResult] = None) -> None:
    app = result.app

    # Header / grade card -------------------------------------------------
    grade_str = s(f" {result.grade} ", _GRADE_COLOR.get(result.grade, "") + _BOLD)
    w(f"  App:        {s(app.name, _BOLD)}  v{app.version}")
    w(f"  Bundle:     {app.bundle_path}")
    elec = app.electron_version or "unknown"
    eol = ""
    if app.electron_eol:
        eol = s("  [END-OF-LIFE]", _SEV_COLOR['high'] + _BOLD)
    w(f"  Electron:   {elec}{eol}")
    if app.electron_eol_note:
        w(s(f"              {app.electron_eol_note}", _DIM))
    sign = {True: "signed", False: "no signature artifacts found",
            None: "unknown (not determinable)"}[app.code_signed]
    w(f"  Signing:    {sign}")
    w(f"  Scanned:    {result.scan_timestamp}")
    w("")
    w(f"  Grade:      {grade_str}   score {result.score}/100")
    w(f"  Confidence: {result.confidence_note}")
    w("─" * 70)

    # Severity rollup -----------------------------------------------------
    w(s("  Severity rollup", _BOLD))
    for sev in Severity:
        count = sum(1 for f in result.findings if f.severity is sev)
        glyph = s(sev.glyph, _SEV_COLOR[sev.value])
        label = s(f"{sev.label:<9}", _SEV_COLOR[sev.value])
        w(f"    {glyph} {label} {count}")
    conf_counts = {c: sum(1 for f in result.findings if f.confidence is c)
                   for c in Confidence}
    w("    " + s("confidence: ", _DIM)
      + "  ".join(f"{c.label.lower()}={conf_counts[c]}" for c in Confidence))
    w("─" * 70)

    # Findings ------------------------------------------------------------
    scored = [f for f in result.findings if f.severity is not Severity.INFO]
    info = [f for f in result.findings if f.severity is Severity.INFO]
    if not scored:
        w(s("  No issues found above informational level for the checks run.",
            _SEV_COLOR['low']))
    for f in scored:
        _render_finding(w, s, f)
    if info:
        w("")
        w(s("  Informational / context", _BOLD))
        for f in info:
            _render_finding(w, s, f, compact=True)

    # Diff ----------------------------------------------------------------
    if diff is not None:
        _render_diff(w, s, diff)

    # Coverage ------------------------------------------------------------
    w("")
    w("─" * 70)
    w(s("  What this DOES cover", _BOLD))
    for item in coverage.COVERS:
        w(f"    + {item}")
    w("")
    w(s("  What this does NOT cover", _BOLD))
    for item in coverage.DOES_NOT_COVER:
        w(f"    - {item}")
    w("")
    w(s("  " + coverage.DISCLAIMER, _DIM))


def _render_efficiency(w, s, result: ScanResult) -> None:
    grade = result.efficiency_grade
    grade_str = s(f" {grade} ", _GRADE_COLOR.get(grade, "") + _BOLD)
    summ = result.size_summary or {}
    impact = result.impact_summary or {}
    w("")
    w("═" * 70)
    w(s("  EFFICIENCY / FOOTPRINT  (static — no runtime profiling)", _BOLD))
    w("═" * 70)
    w(f"  Grade:      {grade_str}   score {result.efficiency_score}/100")
    if summ:
        w(f"  Footprint:  {summ.get('total_human', '?')} "
          f"across {summ.get('file_count', 0)} files")
        bt = summ.get("by_type_human", {})
        if bt:
            top = "  ".join(f"{k}={v}" for k, v in list(bt.items())[:6])
            w(s(f"              {top}", _DIM))
    if result.efficiency_note:
        w(f"  Confidence: {result.efficiency_note}")
    largest = summ.get("largest", [])[:5]
    if largest:
        w("")
        w(s("  Largest files", _BOLD))
        for item in largest:
            w(f"    {item['human']:>9}  {item['path']}")
    w("─" * 70)

    scored = [f for f in result.efficiency_findings if f.severity is not Severity.INFO]
    info = [f for f in result.efficiency_findings if f.severity is Severity.INFO]
    if not scored:
        w(s("  No significant efficiency issues found.", _SEV_COLOR['low']))
    for f in scored:
        _render_finding(w, s, f)
    if info:
        w("")
        w(s("  Informational / context", _BOLD))
        for f in info:
            _render_finding(w, s, f, compact=True)

    # Impact summary ----------------------------------------------------
    if impact:
        w("")
        w("═" * 70)
        w(s("  IMPACT SUMMARY (measured payload size — NOT runtime speed)", _BOLD))
        w("═" * 70)
        w("  " + impact.get("headline", ""))
        wins = impact.get("biggest_wins", [])
        if wins:
            w("")
            w(s("  Biggest wins (per-fix measured savings, ranked)", _BOLD))
            for win in wins:
                tag = win["kind"]
                line = (f"    −{win['human']:>9}  {win['label']}  "
                        f"({win['before_human']} → ~{win['after_human']})  "
                        f"{s('[' + tag + ']', _DIM)}")
                w(line)
                if win.get("assumption"):
                    w(s(f"               {win['assumption']}", _DIM))
        if impact.get("measured_benefits"):
            w("")
            w(s("  Measured benefits", _BOLD))
            for b in impact["measured_benefits"]:
                w(f"    • {b}")
        if impact.get("directional_benefits"):
            w("")
            w(s("  Directional benefits (expected, NOT measured — verify with profiling)", _BOLD))
            for b in impact["directional_benefits"]:
                w(s(f"    → {b}", _DIM))
        if impact.get("disclaimer"):
            w("")
            w(s("  " + impact["disclaimer"], _DIM))


def _render_finding(w, s, f, compact: bool = False) -> None:
    color = _SEV_COLOR[f.severity.value]
    glyph = s(f.severity.glyph, color)
    tag = s(f"{f.severity.label.upper()}", color + _BOLD)
    conf = s(f"[{f.confidence.label}]", _DIM)
    w("")
    w(f"  {glyph} {tag} {conf} {f.title}")
    w(s(f"      id={f.stable_id}  category={f.category}", _DIM))
    w(f"      {s('location ', _DIM)}{f.source_locator.render()}")
    if f.volatile:
        w(s("      (live probe result — excluded from diffs)", _DIM))
    if compact:
        return
    w(f"      {s('evidence ', _DIM)}{_clip(f.evidence)}")
    if f.why_it_matters:
        w(f"      {s('why ', _DIM)}{f.why_it_matters}")
    if f.false_positive_note:
        w(f"      {s('note ', _DIM)}{f.false_positive_note}")
    w(f"      {s('fix ', _DIM)}{f.remediation.summary}")
    if f.remediation.code:
        for ln in f.remediation.code.splitlines():
            w(s(f"        {ln}", _DIM))
    for ref in f.references:
        w(s(f"      ref {ref}", _DIM))


def _render_diff(w, s, diff: DiffResult) -> None:
    w("")
    w("─" * 70)
    w(s("  Diff vs previous report (static findings only)", _BOLD))
    w(f"    fixed={len(diff.fixed)}  new={len(diff.new)}  unchanged={len(diff.unchanged)}")
    for f in diff.new:
        w(s(f"    NEW    [{f['severity']}] {f['title']} ({f['stable_id']})",
            _SEV_COLOR.get(f['severity'], "")))
    for f in diff.fixed:
        w(s(f"    FIXED  [{f['severity']}] {f['title']} ({f['stable_id']})",
            _SEV_COLOR['low']))


def _clip(text: str, width: int = 120) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[:width] + "…"
