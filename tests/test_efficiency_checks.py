"""Efficiency analyzer tests — offline, deterministic, no execution.

Two synthetic fixtures prove the analyzer *discriminates* rather than flagging
everything: a deliberately INEFFICIENT app (un-minified bundle, source maps,
oversized image, duplicate + dev + heavy + unused deps, many startup scripts,
sync fs in main) that must grade poorly, and a LEAN app that must grade well.
"""

import json

from deskscanner.engine import scan
from deskscanner.models import Severity
from helpers import write_asar

# A line short enough to read as un-minified, repeated to exceed the threshold.
_UNMIN = (b"function widget(state) { return state.value + 1 }\n" * 3000)  # ~150 KB
_MIN_LINE = (b"!function(){var a=1;" + b"x=x+1;" * 1000 + b"}();\n")       # one long line


def _png(width: int, height: int, pad: int) -> bytes:
    return (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
            + width.to_bytes(4, "big") + height.to_bytes(4, "big")
            + b"\x00" * pad)


def _inefficient_files() -> dict:
    return {
        "package.json": json.dumps({
            "name": "bloatapp", "version": "1.0.0", "main": "main.js",
            "dependencies": {"moment": "^2.29.0", "unuseddep": "^1.0.0",
                             "usedlib": "^1.0.0"},
            "devDependencies": {"typescript": "^5.0.0"},
        }).encode(),
        # main process: top-level synchronous fs
        "main.js": (b"const fs = require('fs');\n"
                    b"const data = fs.readFileSync('./config.json');\n"
                    b"const u = require('usedlib');\n"
                    b"console.log(u, data);\n"),
        # large un-minified renderer + its shipped source map
        "renderer.js": _UNMIN,
        "renderer.js.map": b'{"version":3,"sources":[]}' + b"A" * (200 * 1024),
        # oversized image
        "assets/splash.png": _png(5000, 4000, 1_700 * 1024),
        # index.html with many startup scripts
        "index.html": (b"<html><head>"
                       + b"<script src=\"a.js\"></script>" * 9
                       + b"</head></html>"),
        # node_modules: dev dep (typescript), heavy dep (moment), duplicate (dup)
        "node_modules/typescript/package.json": b'{"version":"5.4.0"}',
        "node_modules/typescript/tsc.js": b"t" * (300 * 1024),
        "node_modules/moment/package.json": b'{"version":"2.29.4"}',
        "node_modules/moment/moment.js": _MIN_LINE,
        "node_modules/usedlib/package.json": b'{"version":"1.0.0"}',
        "node_modules/usedlib/index.js": _MIN_LINE,
        "node_modules/dup/package.json": b'{"version":"1.0.0"}',
        "node_modules/dup/index.js": _MIN_LINE,
        "node_modules/other/node_modules/dup/package.json": b'{"version":"2.0.0"}',
        "node_modules/other/node_modules/dup/index.js": _MIN_LINE,
        # duplicated identical large files
        "a/big.bin": b"Z" * (300 * 1024),
        "b/big.bin": b"Z" * (300 * 1024),
    }


def _lean_files() -> dict:
    return {
        "package.json": json.dumps({
            "name": "leanapp", "version": "1.0.0", "main": "main.js",
            "dependencies": {"dayjs": "^1.11.0"},
        }).encode(),
        "main.js": b"const d=require('dayjs');module.exports=d;\n",
        "index.js": _MIN_LINE,
        "node_modules/dayjs/package.json": b'{"version":"1.11.10"}',
        "node_modules/dayjs/dayjs.min.js": _MIN_LINE,
        "index.html": b"<html><body><script src=\"index.js\"></script></body></html>",
    }


def _scan(tmp_path, files, name="app.asar", mode="efficiency"):
    p = str(tmp_path / name)
    write_asar(p, files)
    return scan(p, mode=mode, timestamp="T")


def _titles(result):
    return [f.title for f in result.efficiency_findings]


def _discriminators(result):
    return {f.discriminator for f in result.efficiency_findings}


# --------------------------------------------------------------------------- #
def test_inefficient_grades_poorly(tmp_path):
    r = _scan(tmp_path, _inefficient_files())
    assert r.efficiency_grade in ("D", "F")
    assert r.efficiency_score < 70


def test_lean_grades_well(tmp_path):
    r = _scan(tmp_path, _lean_files())
    assert r.efficiency_grade in ("A", "B")
    scored = [f for f in r.efficiency_findings if f.severity is not Severity.INFO]
    assert len(scored) <= 1  # nothing serious on a lean app


def test_analyzer_discriminates(tmp_path):
    bad = _scan(tmp_path, _inefficient_files(), name="bad.asar")
    good = _scan(tmp_path, _lean_files(), name="good.asar")
    assert good.efficiency_score > bad.efficiency_score


def test_each_signal_fires(tmp_path):
    r = _scan(tmp_path, _inefficient_files())
    discs = _discriminators(r)
    # core structural signals
    assert "eff:footprint" in discs
    assert "eff:sourcemaps" in discs
    assert "eff:devdeps" in discs
    assert "eff:unminified:renderer.js" in discs
    assert "eff:dupe:dup" in discs                       # two versions of 'dup'
    assert "eff:unused:unuseddep" in discs
    assert "eff:heavy:moment" in discs
    assert "eff:main-sync-fs" in discs
    assert any(d.startswith("eff:image:") for d in discs)
    assert any(d.startswith("eff:startup-scripts:") for d in discs)
    assert any(d.startswith("eff:dup-content:") for d in discs)


def test_every_finding_has_locator_and_remediation(tmp_path):
    r = _scan(tmp_path, _inefficient_files())
    for f in r.efficiency_findings:
        assert f.source_locator.path, f.title
        assert f.remediation.summary, f.title
        assert f.stable_id.startswith("DS-")


def test_determinism(tmp_path):
    a = _scan(tmp_path, _inefficient_files(), name="x.asar").to_dict()["efficiency"]
    b = _scan(tmp_path, _inefficient_files(), name="y.asar").to_dict()["efficiency"]
    # Same content -> identical findings, grade, and impact numbers.
    assert a == b


def test_impact_summary_measured(tmp_path):
    r = _scan(tmp_path, _inefficient_files())
    im = r.impact_summary
    assert im["current_bytes"] > 0
    assert 0 <= im["projected_bytes"] <= im["current_bytes"]
    assert im["bytes_saved"] == im["current_bytes"] - im["projected_bytes"]
    assert 0 <= im["pct_reduction"] <= 100
    assert im["biggest_wins"], "expected at least one win"
    # Source-map removal is an exactly-measured saving, not an estimate.
    maps = [w for w in im["biggest_wins"] if "source maps" in w["label"].lower()]
    assert maps and maps[0]["kind"] == "measured"
    assert "profiling" in im["disclaimer"].lower()


def test_no_fabricated_runtime_speed_claims(tmp_path):
    """The tool must never claim a runtime speed/FPS percentage."""
    r = _scan(tmp_path, _inefficient_files())
    blob = " ".join(
        f"{f.title} {f.evidence} {f.why_it_matters} {f.remediation.summary}"
        for f in r.efficiency_findings
    ).lower()
    blob += " " + json.dumps(r.impact_summary).lower()
    for banned in ("% faster", "% smoother", "fps", "milliseconds faster",
                   "x faster"):
        assert banned not in blob, f"fabricated runtime claim: {banned!r}"


def test_obfuscation_lowers_unused_confidence(tmp_path):
    """On a largely-minified bundle, 'unused' drops to 'possible' and says so."""
    files = {
        "package.json": json.dumps({
            "name": "min", "version": "1.0.0", "main": "main.js",
            "dependencies": {"ghostdep": "^1.0.0"},
        }).encode(),
        # everything minified -> minified_ratio high -> obfuscated
        "main.js": _MIN_LINE,
        "a.js": _MIN_LINE,
        "b.js": _MIN_LINE,
    }
    r = _scan(tmp_path, files)
    unused = [f for f in r.efficiency_findings if f.discriminator == "eff:unused:ghostdep"]
    assert unused, "expected a possibly-unused finding"
    assert unused[0].confidence.value == "possible"
    assert "minified" in (unused[0].false_positive_note or "").lower()


def test_security_axis_unaffected_in_combined_mode(tmp_path):
    """Efficiency findings must not pollute the security grade/findings."""
    files = _inefficient_files()
    eff_only = _scan(tmp_path, files, name="e.asar", mode="efficiency")
    combined = _scan(tmp_path, files, name="c.asar", mode="all")
    # security axis present in combined, empty in efficiency-only
    assert eff_only.findings == []
    assert eff_only.grade == "N/A"
    assert combined.mode == "all"
    # the efficiency grade is identical whether or not security also ran
    assert combined.efficiency_grade == eff_only.efficiency_grade
    # no efficiency-category finding leaked into the security list
    assert all(f.category != "efficiency" for f in combined.findings)


def test_unpacked_directory_advisory(tmp_path):
    """A directory (unpacked) bundle triggers the asar-packing advisory."""
    root = tmp_path / "app"
    (root / "node_modules" / "dayjs").mkdir(parents=True)
    (root / "package.json").write_text(json.dumps(
        {"name": "u", "version": "1.0.0", "main": "main.js",
         "dependencies": {"dayjs": "^1"}}))
    (root / "main.js").write_text("const d=require('dayjs');\n")
    r = scan(str(root), mode="efficiency", timestamp="T")
    assert "eff:unpacked" in _discriminators(r)
