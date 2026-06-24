"""Report rendering must be XSS-safe against hostile bundle strings."""

import io

from deskscanner.models import (
    AppInfo,
    Confidence,
    Finding,
    Remediation,
    ScanResult,
    Severity,
    SourceLocator,
)
from deskscanner.reporting.cli import render_cli
from deskscanner.reporting.html import render_html

PAYLOAD = '<script>alert(1)</script><img src=x onerror=alert(2)>"><b>x</b>'


def _hostile_result():
    f = Finding(
        title=f"Evil {PAYLOAD}",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category="secrets",
        evidence=f"value={PAYLOAD}",
        source_locator=SourceLocator(f"path/{PAYLOAD}.js", line=3),
        remediation=Remediation(f"fix {PAYLOAD}", code=f"const x = '{PAYLOAD}'"),
        references=["https://example.com"],
        why_it_matters=f"because {PAYLOAD}",
        false_positive_note=f"note {PAYLOAD}",
    )
    app = AppInfo(name=f"App {PAYLOAD}", version="1.0", bundle_path="/x",
                  electron_version="30.0.0")
    return ScanResult(app=app, findings=[f], scan_timestamp="T", grade="C",
                      score=72.0, confidence_note="normal")


def test_html_escapes_hostile_strings():
    html = render_html(_hostile_result())
    # No raw, executable tag may appear verbatim — every '<' from hostile input
    # must have been escaped to '&lt;'.
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "<b>x</b>" not in html
    # The escaped form must be present (proves it was rendered as text).
    assert "&lt;script&gt;" in html


def test_html_is_wellformed_document():
    html = render_html(_hostile_result())
    assert html.strip().startswith("<!doctype html>")
    assert "</html>" in html
    assert 'lang="en"' in html


def test_cli_renders_without_crash_and_no_raw_payload_break():
    buf = io.StringIO()
    render_cli(_hostile_result(), stream=buf)
    out = buf.getvalue()
    assert "Evil" in out
    assert "DS-" in out  # stable id shown
    assert "Grade" in out


def test_html_contains_grade_and_coverage():
    html = render_html(_hostile_result())
    assert "doesn&#39;t cover" in html or "doesn't cover" in html
    assert ">C<" in html  # grade letter rendered
