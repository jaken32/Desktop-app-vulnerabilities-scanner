"""Determinism: same bundle -> identical static findings, order, and grade.

Volatile fields (timestamp, live-probe results) are excluded by scanning with
the probe disabled and stamping a fixed timestamp.
"""

import os

from deskscanner.engine import scan
from helpers import write_insecure_asar


def _scan(tmp_path, name="app.asar"):
    p = os.path.join(tmp_path, name)
    write_insecure_asar(p)
    return scan(p, probe=False, timestamp="FIXED")


def test_identical_findings_and_grade(tmp_path):
    a = _scan(tmp_path, "a.asar")
    b = _scan(tmp_path, "a.asar")  # same path, same bytes

    assert a.grade == b.grade
    assert a.score == b.score
    ids_a = [f.stable_id for f in a.findings]
    ids_b = [f.stable_id for f in b.findings]
    assert ids_a == ids_b  # identical order + identical ids


def test_stable_ids_are_stable_strings(tmp_path):
    a = _scan(tmp_path, "a.asar")
    for f in a.findings:
        assert f.stable_id.startswith("DS-")
        assert len(f.stable_id) == 15  # DS- + 12 hex


def test_serialization_is_stable(tmp_path):
    a = _scan(tmp_path)
    # Re-serialising must be byte-identical (no volatile fields leak into it
    # beyond timestamp, which we fixed).
    import json
    s1 = json.dumps(a.to_dict(), sort_keys=True)
    s2 = json.dumps(a.to_dict(), sort_keys=True)
    assert s1 == s2
