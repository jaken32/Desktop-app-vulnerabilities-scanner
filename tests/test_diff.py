"""Diff mode: fixed / new / unchanged, ignoring volatile fields."""

from deskscanner.diff import diff_reports
from deskscanner.models import (
    Confidence,
    Finding,
    Remediation,
    ScanResult,
    AppInfo,
    Severity,
    SourceLocator,
)


def _f(disc, volatile=False, sev=Severity.HIGH):
    return Finding(
        title=f"t-{disc}", severity=sev, confidence=Confidence.CONFIRMED,
        category="c", evidence="e", source_locator=SourceLocator("p", line=1),
        remediation=Remediation("fix"), discriminator=disc, volatile=volatile,
    )


def _result(findings, ts):
    return ScanResult(app=AppInfo(name="t"), findings=findings, scan_timestamp=ts)


def test_new_fixed_unchanged():
    prev = _result([_f("a"), _f("b")], "T1")
    curr = _result([_f("b"), _f("c")], "T2")
    d = diff_reports(prev, curr)
    titles = lambda items: {x["title"] for x in items}
    assert titles(d.fixed) == {"t-a"}
    assert titles(d.new) == {"t-c"}
    assert titles(d.unchanged) == {"t-b"}
    assert d.has_changes()


def test_volatile_findings_ignored():
    prev = _result([_f("a"), _f("vol", volatile=True)], "T1")
    curr = _result([_f("a")], "T2")  # volatile gone, but it should be ignored
    d = diff_reports(prev, curr)
    assert not d.has_changes()
    assert d.fixed == [] and d.new == []


def test_timestamp_ignored():
    prev = _result([_f("a")], "T1")
    curr = _result([_f("a")], "DIFFERENT")
    d = diff_reports(prev, curr)
    assert not d.has_changes()


def test_accepts_serialised_dicts():
    prev = _result([_f("a")], "T1").to_dict()
    curr = _result([_f("a"), _f("b")], "T2").to_dict()
    d = diff_reports(prev, curr)
    assert len(d.new) == 1 and d.new[0]["title"] == "t-b"
