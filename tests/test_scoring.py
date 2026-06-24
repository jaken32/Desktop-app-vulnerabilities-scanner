"""Scoring rubric + confidence weighting."""

from deskscanner.models import (
    Confidence,
    Finding,
    Remediation,
    Severity,
    SourceLocator,
)
from deskscanner.scoring import compute_score


def _f(severity, confidence, disc=""):
    return Finding(
        title=f"t-{disc}", severity=severity, confidence=confidence,
        category="c", evidence="e", source_locator=SourceLocator("p", line=1),
        remediation=Remediation("fix"), discriminator=disc,
    )


def test_grade_bands_empty_is_a():
    s = compute_score([])
    assert s.grade == "A" and s.value == 100.0


def test_single_confirmed_critical_is_f():
    s = compute_score([_f(Severity.CRITICAL, Confidence.CONFIRMED)])
    assert s.grade == "F"


def test_confirmed_medium_stays_high_grade():
    s = compute_score([_f(Severity.MEDIUM, Confidence.CONFIRMED)])
    assert s.grade in ("A", "B")


def test_low_confidence_does_not_dominate():
    # A single 'possible' high must NOT tank the grade the way a confirmed one would.
    possible = compute_score([_f(Severity.HIGH, Confidence.POSSIBLE)])
    confirmed = compute_score([_f(Severity.HIGH, Confidence.CONFIRMED)])
    assert possible.value > confirmed.value
    assert possible.grade in ("A", "B")


def test_many_possibles_do_not_outweigh_one_critical():
    possibles = compute_score([_f(Severity.MEDIUM, Confidence.POSSIBLE, str(i))
                               for i in range(10)])
    one_crit = compute_score([_f(Severity.CRITICAL, Confidence.CONFIRMED)])
    assert one_crit.value < possibles.value


def test_info_does_not_affect_grade():
    s = compute_score([_f(Severity.INFO, Confidence.CONFIRMED, str(i)) for i in range(20)])
    assert s.value == 100.0


def test_diminishing_returns():
    # Two criticals are worse than one, but not double the penalty.
    one = 100 - compute_score([_f(Severity.CRITICAL, Confidence.CONFIRMED, "1")]).value
    two = 100 - compute_score([_f(Severity.CRITICAL, Confidence.CONFIRMED, "1"),
                               _f(Severity.CRITICAL, Confidence.CONFIRMED, "2")]).value
    assert one < two < 2 * one


def test_rollup_counts():
    s = compute_score([_f(Severity.HIGH, Confidence.CONFIRMED, "1"),
                       _f(Severity.HIGH, Confidence.LIKELY, "2"),
                       _f(Severity.LOW, Confidence.POSSIBLE, "3")])
    assert s.rollup["high"] == 2
    assert s.rollup["low"] == 1


def test_minified_confidence_note():
    s = compute_score([], minified_ratio=0.8)
    assert "minified" in s.confidence_note
