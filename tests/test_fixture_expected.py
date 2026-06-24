"""The insecure fixture must produce EXACTLY the documented findings; the
secure fixture must grade well. This is the end-to-end proof the tool works.

The expected set is documented in tests/fixtures/EXPECTED.md.
"""

import collections
import os

from deskscanner.engine import scan
from deskscanner.models import Severity
from helpers import write_insecure_asar, write_secure_asar

# (category, severity, confidence) -> count. This is the exact, documented
# expectation for the insecure fixture (probe disabled).
EXPECTED_INSECURE = {
    ("electron_config", "critical", "confirmed"): 1,   # nodeIntegration + remote (RCE)
    ("electron_config", "high", "confirmed"): 5,       # contextIso, webSec, allowInsecure, remoteModule, webview
    ("electron_config", "high", "likely"): 1,          # contextBridge broad exposure
    ("electron_config", "medium", "confirmed"): 1,     # sandbox disabled
    ("electron_config", "medium", "likely"): 1,        # missing CSP
    ("electron_config", "medium", "possible"): 1,      # shell.openExternal non-literal
    ("electron_config", "info", "confirmed"): 1,       # preload present
    ("secrets", "critical", "confirmed"): 2,           # AWS key id + private key
    ("secrets", "high", "possible"): 1,                # generic client_secret
    ("dependencies", "medium", "likely"): 1,           # electron outdated major
    ("dependencies", "low", "likely"): 1,              # lodash outdated major
    ("dependencies", "info", "confirmed"): 1,          # CVE scope note
    ("app_meta", "high", "confirmed"): 1,              # EOL Electron 22
    ("app_meta", "info", "confirmed"): 1,              # code-signing unknown
}


def test_insecure_fixture_exact_findings(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_insecure_asar(p)
    result = scan(p, probe=False, timestamp="FIXED")

    actual = collections.Counter(
        (f.category, f.severity.value, f.confidence.value) for f in result.findings
    )
    assert dict(actual) == EXPECTED_INSECURE

    # Grade must be F (it contains confirmed RCE + usable credentials).
    assert result.grade == "F"


def test_insecure_every_finding_has_locator_and_confidence(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_insecure_asar(p)
    result = scan(p, probe=False, timestamp="FIXED")
    for f in result.findings:
        assert f.source_locator.render(), f"missing locator: {f.title}"
        assert f.confidence is not None
        assert f.stable_id


def test_no_fabricated_cve_anywhere(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_insecure_asar(p)
    result = scan(p, probe=False, timestamp="FIXED")
    for f in result.findings:
        assert "CVE-" not in f.title
        assert "CVE-" not in f.evidence


def test_secure_fixture_grades_well(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_secure_asar(p)
    result = scan(p, probe=False, timestamp="FIXED")

    scored = [f for f in result.findings if f.severity is not Severity.INFO]
    assert scored == [], f"secure fixture should have no scored findings: {scored}"
    assert result.grade == "A"
    assert result.score == 100.0


def test_electron_version_and_eol_detected(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_insecure_asar(p)
    result = scan(p, probe=False, timestamp="FIXED")
    assert result.app.electron_version == "22.0.0"
    assert result.app.electron_eol is True
