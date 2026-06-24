"""Polished, branded PDF report.

Built with fpdf2 (pure Python, no system libraries) so it produces a designed,
colour-coded document — branded header band, grade badge, severity rollup,
optional AI narrative, and colour-tagged findings — without the heavy native
dependencies an HTML-to-PDF pipeline would need.

fpdf2's core fonts are Latin-1; all bundle-derived and AI-derived text is passed
through :func:`_latin1`, which maps the report glyphs to ASCII and replaces any
remaining out-of-range characters, so hostile or exotic content can never crash
rendering.
"""

from __future__ import annotations

from typing import Any, Optional

from ..models import ScanResult, Severity
from . import coverage

# Brand palette (RGB). Deep indigo brand with colourblind-safe severity hues.
_BRAND = (37, 47, 74)
_BRAND_ACCENT = (94, 160, 239)
_INK = (26, 29, 35)
_MUTED = (110, 118, 130)
_RULE = (220, 224, 230)
_SEV_RGB = {
    "critical": (176, 0, 32),
    "high": (192, 86, 33),
    "medium": (138, 109, 0),
    "low": (11, 110, 153),
    "info": (110, 118, 130),
}
_GRADE_RGB = {"A": (26, 127, 55), "B": (26, 127, 55), "C": (138, 109, 0),
              "D": (192, 86, 33), "F": (176, 0, 32)}

_GLYPHS = {
    "✖": "x", "▲": "!", "●": "o", "○": "o", "·": "-", "⏎": " ",
    "→": "->", "—": "-", "–": "-", "…": "...", "“": '"', "”": '"',
    "‘": "'", "’": "'", "•": "-", " ": " ",
}


def _latin1(text: Any) -> str:
    """Make any string safe for fpdf2's Latin-1 core fonts."""
    s = str(text)
    for bad, good in _GLYPHS.items():
        s = s.replace(bad, good)
    return s.encode("latin-1", "replace").decode("latin-1")


def _require_fpdf():
    try:
        from fpdf import FPDF
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError(
            "The 'fpdf2' package is required for PDF reports. Install the report "
            "extra: pip install -e \".[report]\""
        ) from exc
    return FPDF


class _Report:  # thin wrapper around the lazily-imported FPDF base
    def __init__(self, result: ScanResult):
        FPDF = _require_fpdf()
        self.result = result

        class _PDF(FPDF):
            def footer(inner) -> None:
                inner.set_y(-12)
                inner.set_font("Helvetica", "", 7)
                inner.set_text_color(*_MUTED)
                left = "deskscanner - static analysis + safe loopback inspection"
                inner.cell(0, 6, _latin1(left), align="L")
                inner.cell(0, 6, f"Page {inner.page_no()}/{{nb}}", align="R")

        self.pdf = _PDF(format="A4", unit="mm")
        self.pdf.set_auto_page_break(auto=True, margin=18)
        self.pdf.set_title(_latin1(f"deskscanner report - {result.app.name}"))
        self.pdf.alias_nb_pages()

    # -- low-level helpers ------------------------------------------------- #
    @property
    def _w(self) -> float:
        return self.pdf.w - self.pdf.l_margin - self.pdf.r_margin

    def _h2(self, text: str) -> None:
        p = self.pdf
        p.ln(3)
        p.set_font("Helvetica", "B", 13)
        p.set_text_color(*_BRAND)
        p.cell(0, 8, _latin1(text), new_x="LMARGIN", new_y="NEXT")
        p.set_draw_color(*_RULE)
        y = p.get_y()
        p.line(p.l_margin, y, p.l_margin + self._w, y)
        p.ln(2)

    def _body(self, text: str) -> None:
        p = self.pdf
        p.set_font("Helvetica", "", 10)
        p.set_text_color(*_INK)
        for para in (text or "").split("\n"):
            p.multi_cell(0, 5, _latin1(para) or " ", new_x="LMARGIN", new_y="NEXT")
            p.ln(1)

    def _bullets(self, items: list[str], color=None) -> None:
        p = self.pdf
        p.set_font("Helvetica", "", 10)
        for item in items:
            p.set_text_color(*(color or _BRAND_ACCENT))
            p.cell(5, 5, _latin1("-"))
            p.set_text_color(*_INK)
            p.multi_cell(self._w - 5, 5, _latin1(item), new_x="LMARGIN", new_y="NEXT")
            p.ln(0.5)

    # -- sections ---------------------------------------------------------- #
    def _header(self) -> None:
        p, r = self.pdf, self.result
        p.set_fill_color(*_BRAND)
        p.rect(0, 0, p.w, 30, style="F")
        p.set_xy(p.l_margin, 8)
        p.set_font("Helvetica", "B", 20)
        p.set_text_color(255, 255, 255)
        p.cell(0, 9, "deskscanner", new_x="LMARGIN", new_y="NEXT")
        p.set_x(p.l_margin)
        p.set_font("Helvetica", "", 10)
        p.set_text_color(*_BRAND_ACCENT)
        p.cell(0, 6, "Electron application security report", new_x="LMARGIN", new_y="NEXT")
        p.ln(8)

    def _grade_card(self) -> None:
        p, r = self.pdf, self.result
        app = r.app
        top = p.get_y()
        # Grade badge
        gcol = _GRADE_RGB.get(r.grade, _MUTED)
        p.set_fill_color(*gcol)
        p.rect(p.l_margin, top, 26, 26, style="F", round_corners=True, corner_radius=3)
        p.set_xy(p.l_margin, top + 4)
        p.set_font("Helvetica", "B", 22)
        p.set_text_color(255, 255, 255)
        p.cell(26, 12, _latin1(r.grade), align="C")
        p.set_xy(p.l_margin, top + 16)
        p.set_font("Helvetica", "", 8)
        p.cell(26, 6, f"{r.score}/100", align="C")
        # Details to the right
        x = p.l_margin + 32
        p.set_xy(x, top)
        p.set_font("Helvetica", "B", 14)
        p.set_text_color(*_INK)
        p.cell(0, 7, _latin1(f"{app.name}  v{app.version}"), new_x="LMARGIN", new_y="NEXT")
        rows = [
            ("Bundle", app.bundle_path or "-"),
            ("Electron", (app.electron_version or "unknown")
             + ("  [END-OF-LIFE]" if app.electron_eol else "")),
            ("Signing", {True: "signed", False: "no signature artifacts found",
                         None: "unknown"}[app.code_signed]),
            ("Scanned", r.scan_timestamp or "-"),
        ]
        p.set_font("Helvetica", "", 9)
        for label, val in rows:
            p.set_x(x)
            p.set_text_color(*_MUTED)
            p.cell(22, 5, _latin1(f"{label}"))
            p.set_text_color(*_INK)
            p.multi_cell(self._w - 32 - 22, 5, _latin1(val), new_x="LMARGIN", new_y="NEXT")
        p.set_y(max(p.get_y(), top + 28))
        if r.confidence_note:
            p.set_font("Helvetica", "I", 8)
            p.set_text_color(*_MUTED)
            p.multi_cell(0, 4, _latin1("Confidence: " + r.confidence_note),
                         new_x="LMARGIN", new_y="NEXT")
        p.ln(2)

    def _rollup(self) -> None:
        p, r = self.pdf, self.result
        self._h2("Severity rollup")
        chip = (self._w - 4 * 4) / 5
        x0 = p.l_margin
        y = p.get_y()
        for i, sev in enumerate(Severity):
            count = sum(1 for f in r.findings if f.severity is sev)
            col = _SEV_RGB[sev.value]
            x = x0 + i * (chip + 4)
            p.set_fill_color(*col)
            p.rect(x, y, chip, 14, style="F", round_corners=True, corner_radius=2)
            p.set_xy(x, y + 1.5)
            p.set_font("Helvetica", "B", 13)
            p.set_text_color(255, 255, 255)
            p.cell(chip, 7, str(count), align="C")
            p.set_xy(x, y + 8.5)
            p.set_font("Helvetica", "", 7)
            p.cell(chip, 4, _latin1(sev.label), align="C")
        p.set_y(y + 18)

    def _analysis(self, analysis) -> None:
        if analysis is None:
            return
        if analysis.plain_english:
            self._h2("Plain-English summary")
            self._body(analysis.plain_english)
        if analysis.key_risks:
            self._h2("Key risks")
            self._bullets(analysis.key_risks, color=_SEV_RGB["high"])
        if analysis.in_depth:
            self._h2("In-depth analysis")
            self._body(analysis.in_depth)
        if analysis.recommendations:
            self._h2("Recommendations")
            self._bullets(analysis.recommendations)
        self.pdf.set_font("Helvetica", "I", 7)
        self.pdf.set_text_color(*_MUTED)
        self.pdf.multi_cell(
            0, 4,
            _latin1(f"AI analysis generated by {analysis.model}. It interprets the "
                    "findings below; always verify against the evidence."),
            new_x="LMARGIN", new_y="NEXT")

    def _findings(self) -> None:
        p, r = self.pdf, self.result
        self._h2("Findings")
        scored = [f for f in r.findings if f.severity is not Severity.INFO]
        if not scored:
            p.set_font("Helvetica", "", 10)
            p.set_text_color(*_SEV_RGB["low"])
            p.multi_cell(0, 5, _latin1("No issues found above informational level "
                                       "for the checks run."),
                         new_x="LMARGIN", new_y="NEXT")
        for f in scored:
            self._finding(f)
        info = [f for f in r.findings if f.severity is Severity.INFO]
        if info:
            self._h2("Informational / context")
            for f in info:
                self._finding(f, compact=True)

    def _finding(self, f, compact: bool = False) -> None:
        p = self.pdf
        col = _SEV_RGB[f.severity.value]
        p.ln(1)
        top = p.get_y()
        # severity tag
        p.set_fill_color(*col)
        p.set_font("Helvetica", "B", 8)
        p.set_text_color(255, 255, 255)
        tag = f" {f.severity.label.upper()} "
        tw = p.get_string_width(tag) + 2
        p.rect(p.l_margin, top, tw, 5.5, style="F", round_corners=True, corner_radius=1)
        p.set_xy(p.l_margin, top + 0.6)
        p.cell(tw, 4.5, _latin1(tag), align="C")
        # title
        p.set_xy(p.l_margin + tw + 2, top)
        p.set_font("Helvetica", "B", 10)
        p.set_text_color(*_INK)
        p.multi_cell(self._w - tw - 2, 5.5, _latin1(f.title),
                     new_x="LMARGIN", new_y="NEXT")
        # meta line
        p.set_font("Helvetica", "", 8)
        p.set_text_color(*_MUTED)
        meta = f"{f.confidence.label} | {f.category} | {f.source_locator.render()}"
        p.multi_cell(0, 4, _latin1(meta), new_x="LMARGIN", new_y="NEXT")
        if compact:
            return

        def field(label: str, value: str) -> None:
            if not value:
                return
            p.set_font("Helvetica", "B", 8)
            p.set_text_color(*_MUTED)
            p.cell(16, 4.5, _latin1(label))
            p.set_font("Helvetica", "", 8)
            p.set_text_color(*_INK)
            p.multi_cell(self._w - 16, 4.5, _latin1(value),
                         new_x="LMARGIN", new_y="NEXT")

        field("evidence", f.evidence)
        field("why", f.why_it_matters)
        if f.false_positive_note:
            field("note", f.false_positive_note)
        field("fix", f.remediation.summary)
        p.set_draw_color(*_RULE)
        y = p.get_y() + 1
        p.line(p.l_margin, y, p.l_margin + self._w, y)
        p.ln(1)

    def _coverage(self) -> None:
        self._h2("What this covers")
        self._bullets(list(coverage.COVERS), color=_SEV_RGB["low"])
        self._h2("What this does NOT cover")
        self._bullets(list(coverage.DOES_NOT_COVER), color=_MUTED)
        p = self.pdf
        p.ln(1)
        p.set_font("Helvetica", "I", 8)
        p.set_text_color(*_MUTED)
        p.multi_cell(0, 4, _latin1(coverage.DISCLAIMER), new_x="LMARGIN", new_y="NEXT")

    # -- build ------------------------------------------------------------- #
    def build(self, analysis=None) -> bytes:
        self.pdf.add_page()
        self._header()
        if self.result.ran_security:
            self._grade_card()
            self._rollup()
            self._analysis(analysis)
            self._findings()
            self._coverage()
        if self.result.ran_efficiency:
            self._efficiency()
        out = self.pdf.output()
        return bytes(out)

    # -- efficiency axis --------------------------------------------------- #
    def _efficiency(self) -> None:
        p, r = self.pdf, self.result
        summ = r.size_summary or {}
        impact = r.impact_summary or {}
        self._h2("Efficiency / footprint (static — no runtime profiling)")
        gcol = _GRADE_RGB.get(r.efficiency_grade, _MUTED)
        p.set_font("Helvetica", "B", 12)
        p.set_text_color(*gcol)
        p.cell(0, 7, _latin1(f"Grade {r.efficiency_grade}  ·  "
                             f"{r.efficiency_score}/100"),
               new_x="LMARGIN", new_y="NEXT")
        p.set_font("Helvetica", "", 9)
        p.set_text_color(*_INK)
        if summ:
            p.multi_cell(0, 5, _latin1(
                f"Footprint: {summ.get('total_human','?')} across "
                f"{summ.get('file_count',0)} files. "
                + "  ".join(f"{k}={v}" for k, v in
                            list(summ.get('by_type_human', {}).items())[:6])),
                new_x="LMARGIN", new_y="NEXT")
        if r.efficiency_note:
            p.set_font("Helvetica", "I", 8)
            p.set_text_color(*_MUTED)
            p.multi_cell(0, 4, _latin1("Confidence: " + r.efficiency_note),
                         new_x="LMARGIN", new_y="NEXT")
        p.ln(1)

        scored = [f for f in r.efficiency_findings if f.severity is not Severity.INFO]
        info = [f for f in r.efficiency_findings if f.severity is Severity.INFO]
        if not scored:
            p.set_font("Helvetica", "", 10)
            p.set_text_color(*_SEV_RGB["low"])
            p.multi_cell(0, 5, _latin1("No significant efficiency issues found."),
                         new_x="LMARGIN", new_y="NEXT")
        for f in scored:
            self._finding(f)
        for f in info:
            self._finding(f, compact=True)

        if impact:
            self._h2("Impact summary (measured payload size — not runtime speed)")
            p.set_font("Helvetica", "", 9)
            p.set_text_color(*_INK)
            p.multi_cell(0, 5, _latin1(impact.get("headline", "")),
                         new_x="LMARGIN", new_y="NEXT")
            p.ln(1)
            for w in impact.get("biggest_wins", []):
                p.set_font("Helvetica", "B", 8)
                p.cell(22, 4.5, _latin1(f"-{w['human']}"))
                p.set_font("Helvetica", "", 8)
                p.multi_cell(self._w - 22, 4.5, _latin1(
                    f"{w['label']} ({w['before_human']} -> ~{w['after_human']}) "
                    f"[{w['kind']}]"
                    + (f" - {w['assumption']}" if w.get("assumption") else "")),
                    new_x="LMARGIN", new_y="NEXT")
            if impact.get("measured_benefits"):
                p.ln(1)
                p.set_font("Helvetica", "B", 9)
                p.set_text_color(*_INK)
                p.cell(0, 5, _latin1("Measured benefits"), new_x="LMARGIN", new_y="NEXT")
                p.set_font("Helvetica", "", 8)
                for b in impact["measured_benefits"]:
                    p.multi_cell(0, 4.5, _latin1("- " + b), new_x="LMARGIN", new_y="NEXT")
            if impact.get("directional_benefits"):
                p.ln(1)
                p.set_font("Helvetica", "B", 9)
                p.cell(0, 5, _latin1("Directional benefits (expected, NOT measured)"),
                       new_x="LMARGIN", new_y="NEXT")
                p.set_font("Helvetica", "", 8)
                p.set_text_color(*_MUTED)
                for b in impact["directional_benefits"]:
                    p.multi_cell(0, 4.5, _latin1("-> " + b), new_x="LMARGIN", new_y="NEXT")
            p.ln(1)
            p.set_font("Helvetica", "I", 8)
            p.set_text_color(*_MUTED)
            if impact.get("disclaimer"):
                p.multi_cell(0, 4, _latin1(impact["disclaimer"]),
                             new_x="LMARGIN", new_y="NEXT")


def render_pdf(result: ScanResult, *, analysis: Any = None) -> bytes:
    """Render ``result`` (optionally with an :class:`~.analysis.Analysis`) to PDF bytes."""
    return _Report(result).build(analysis=analysis)


def write_pdf(result: ScanResult, path: str, *, analysis: Any = None) -> None:
    """Render and write a PDF report to ``path``."""
    with open(path, "wb") as fp:
        fp.write(render_pdf(result, analysis=analysis))
