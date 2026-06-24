"""The PDF report must render to a valid document and survive hostile/exotic
bundle strings (it never executes them, but it must not crash on them)."""

from deskscanner.models import (
    AppInfo,
    Confidence,
    Finding,
    Remediation,
    ScanResult,
    Severity,
    SourceLocator,
)
from deskscanner.reporting.analysis import Analysis
from deskscanner.reporting.pdf import _latin1, render_pdf

# Non-Latin-1 + report glyphs that must not crash the Latin-1 core fonts.
# Built from escapes so the test source stays pure ASCII.
NASTY = (
    "Ω 漢字 — … ✖ ▲ "
    "“quote” → emoji \U0001f600"
)


def _result():
    f = Finding(
        title=f"Insecure thing {NASTY}",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        category="electron",
        evidence=f"nodeIntegration=true {NASTY}",
        source_locator=SourceLocator(f"main/{NASTY}.js", line=12),
        remediation=Remediation("Disable nodeIntegration."),
        why_it_matters=f"Renderer gets Node access {NASTY}",
    )
    info = Finding(
        title="Context note",
        severity=Severity.INFO,
        confidence=Confidence.POSSIBLE,
        category="meta",
        evidence="just context",
        source_locator=SourceLocator("app.asar"),
        remediation=Remediation("none"),
    )
    app = AppInfo(name=f"App {NASTY}", version="2.1", bundle_path="/Applications/X",
                  electron_version="22.0.0", electron_eol=True, code_signed=False)
    return ScanResult(app=app, findings=[f, info], scan_timestamp="2026-06-24T00:00:00Z",
                      grade="F", score=18.0, confidence_note="normal confidence")


def test_latin1_maps_glyphs_and_replaces_exotic():
    out = _latin1("✖ ▲ — … 漢字")
    assert "✖" not in out and "—" not in out and "漢" not in out
    assert out.encode("latin-1")  # must be encodable now


def test_render_pdf_is_valid_document():
    data = render_pdf(_result())
    assert isinstance(data, bytes)
    assert data[:5] == b"%PDF-"
    assert b"%%EOF" in data
    assert len(data) > 2000  # a real, multi-element page, not an empty stub


def test_render_pdf_with_analysis_includes_more_content():
    base = render_pdf(_result())
    analysis = Analysis(
        plain_english="The app has a serious setting turned on.",
        in_depth="nodeIntegration enabled means renderer code can reach the OS.",
        key_risks=["Remote content could run native code."],
        recommendations=["Turn off nodeIntegration.", "Enable contextIsolation."],
        model="claude-opus-4-8",
    )
    with_ai = render_pdf(_result(), analysis=analysis)
    assert with_ai[:5] == b"%PDF-"
    assert len(with_ai) > len(base)  # the narrative adds pages/content
