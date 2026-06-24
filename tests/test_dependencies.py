"""Dependency analysis: outdated majors from version numbers; NO fabricated CVEs."""

import os

from deskscanner.checks.base import CheckContext
from deskscanner.checks.dependencies import DependenciesCheck, _version_in_range
from deskscanner.models import AppInfo, Severity
from deskscanner.unpack import load_asar
from helpers import write_asar
from packaging.version import Version


def _run(tmp_path, files):
    p = os.path.join(tmp_path, "a.asar")
    write_asar(p, {k: v.encode() for k, v in files.items()})
    ctx = CheckContext(bundle=load_asar(p), app=AppInfo(name="t"))
    return DependenciesCheck().run(ctx)


def test_outdated_major_flagged(tmp_path):
    pkg = '{"name":"x","version":"1.0.0","dependencies":{"lodash":"^3.10.1"}}'
    findings = _run(tmp_path, {"package.json": pkg})
    outdated = [f for f in findings if "Outdated major" in f.title and "lodash" in f.title]
    assert outdated
    assert outdated[0].false_positive_note  # pin may be intentional


def test_far_behind_is_medium(tmp_path):
    pkg = '{"name":"x","version":"1.0.0","devDependencies":{"electron":"^22.0.0"}}'
    findings = _run(tmp_path, {"package.json": pkg})
    e = [f for f in findings if "electron" in f.title and "Outdated" in f.title]
    assert e and e[0].severity is Severity.MEDIUM


def test_current_major_not_flagged(tmp_path):
    pkg = '{"name":"x","version":"1.0.0","dependencies":{"react":"^19.0.0"}}'
    findings = _run(tmp_path, {"package.json": pkg})
    assert not [f for f in findings if "Outdated major" in f.title]


def test_no_fabricated_cve(tmp_path):
    # With an empty advisory list, NO named-CVE finding may ever appear.
    pkg = '{"name":"x","version":"1.0.0","dependencies":{"lodash":"^3.0.0"}}'
    findings = _run(tmp_path, {"package.json": pkg})
    for f in findings:
        assert "CVE-" not in f.title
        assert "CVE-" not in f.evidence
    # The honest scope note must be present.
    assert any("CVE matching scope" in f.title for f in findings)


def test_lockfile_version_used(tmp_path):
    pkg = '{"name":"x","version":"1.0.0","dependencies":{"lodash":"^3.0.0"}}'
    lock = ('{"name":"x","lockfileVersion":3,"packages":'
            '{"node_modules/lodash":{"version":"3.10.1"}}}')
    findings = _run(tmp_path, {"package.json": pkg, "package-lock.json": lock})
    e = [f for f in findings if "lodash" in f.title and "Outdated" in f.title]
    assert e and "3.10.1" in e[0].title


def test_version_in_range():
    assert _version_in_range(Version("1.2.0"), "<1.3.0")
    assert not _version_in_range(Version("1.4.0"), "<1.3.0")
    assert _version_in_range(Version("1.2.0"), ">=1.0.0 <1.3.0")
    assert not _version_in_range(Version("1.2.0"), "")
