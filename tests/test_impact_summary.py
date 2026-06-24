"""Impact Summary tests — exact, deterministic numbers traced to file sizes,
and a hard guard that no fabricated runtime/speed metric is ever emitted.

The fixture uses precisely-sized files so the projected size and per-fix savings
can be asserted exactly (recomputed from the same reduction constants the
analyzer uses — no magic numbers duplicated here)."""

import json

from deskscanner.checks import efficiency as eff
from deskscanner.engine import scan
from helpers import write_asar

_RENDERER_LINE = b"var xx=1;\n"          # exactly 10 bytes, reads as un-minified
RENDERER_BYTES = len(_RENDERER_LINE) * 11_000
MAP_BYTES = 1_000_000
IMAGE_BYTES = 1_600_000
DEV_JS_BYTES = 500_000
DUP_BYTES = 300_000


def _png(total: int) -> bytes:
    head = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
            + (3000).to_bytes(4, "big") + (2000).to_bytes(4, "big"))
    return head + b"\x00" * (total - len(head))


def _inefficient_files() -> dict:
    return {
        "package.json": json.dumps({
            "name": "sized", "version": "1.0.0", "main": "noop.js",
            "dependencies": {},
            "devDependencies": {"typescript": "^5.0.0"},
        }).encode(),
        "renderer.js": _RENDERER_LINE * 11_000,                    # exactly RENDERER_BYTES
        "renderer.js.map": b"x" * MAP_BYTES,
        "assets/splash.png": _png(IMAGE_BYTES),
        "node_modules/typescript/package.json": b'{"version":"5.4.0"}',
        "node_modules/typescript/tsc.js": b"t" * DEV_JS_BYTES,
        "dir1/dup.bin": b"Z" * DUP_BYTES,
        "dir2/dup.bin": b"Z" * DUP_BYTES,
    }


def _lean_files() -> dict:
    return {
        "package.json": json.dumps({
            "name": "lean", "version": "1.0.0", "main": "main.js",
            "dependencies": {"dayjs": "^1.11.0"},
        }).encode(),
        "main.js": b"const d=require('dayjs');module.exports=d;\n",
        "node_modules/dayjs/package.json": b'{"version":"1.11.10"}',
        "node_modules/dayjs/dayjs.min.js": b"!function(){}();\n",
    }


def _impact(tmp_path, files, name="app.asar"):
    p = str(tmp_path / name)
    write_asar(p, files)
    return scan(p, mode="efficiency", timestamp="T").impact_summary


def _win(impact, needle):
    for w in impact["per_fix"]:
        if needle in w["label"]:
            return w
    raise AssertionError(f"no per-fix item matching {needle!r}")


# --------------------------------------------------------------------------- #
def test_current_size_is_measured_sum(tmp_path):
    files = _inefficient_files()
    impact = _impact(tmp_path, files)
    assert impact["current_bytes"] == sum(len(v) for v in files.values())
    assert impact["lean"] is False


def test_source_map_saving_is_exact_and_measured(tmp_path):
    w = _win(_impact(tmp_path, _inefficient_files()), "source maps")
    assert w["before_bytes"] == MAP_BYTES
    assert w["after_bytes"] == 0            # removed
    assert w["bytes_saved"] == MAP_BYTES
    assert w["kind"] == "measured"


def test_minify_saving_before_after_and_labeled_estimate(tmp_path):
    w = _win(_impact(tmp_path, _inefficient_files()), "Minify renderer.js")
    after = int(RENDERER_BYTES * (1 - eff.MINIFY_REDUCTION))
    assert w["before_bytes"] == RENDERER_BYTES
    assert w["after_bytes"] == after
    assert w["bytes_saved"] == RENDERER_BYTES - after
    assert w["kind"] == "estimate"
    assert "minification" in w["assumption"].lower()


def test_image_saving_is_labeled_estimate_with_assumption(tmp_path):
    w = _win(_impact(tmp_path, _inefficient_files()), "Recompress")
    assert w["before_bytes"] == IMAGE_BYTES
    assert w["after_bytes"] == int(IMAGE_BYTES * (1 - eff.IMAGE_REDUCTION))
    assert w["kind"] == "estimate"
    assert w["assumption"]


def test_devdeps_saving_measured_and_in_benefits(tmp_path):
    impact = _impact(tmp_path, _inefficient_files())
    w = _win(impact, "devDependencies")
    # measured = every byte under node_modules/typescript/
    expected = DEV_JS_BYTES + len(b'{"version":"5.4.0"}')
    assert w["before_bytes"] == expected
    assert w["after_bytes"] == 0
    assert w["kind"] == "measured"
    assert any("devDependencies pruned" in b for b in impact["measured_benefits"])


def test_projected_equals_current_minus_total_savings(tmp_path):
    impact = _impact(tmp_path, _inefficient_files())
    total_saved = sum(w["bytes_saved"] for w in impact["per_fix"])
    assert impact["bytes_saved"] == min(total_saved, impact["current_bytes"])
    assert impact["projected_bytes"] == impact["current_bytes"] - impact["bytes_saved"]
    assert 0 <= impact["pct_reduction"] <= 100
    assert "payload size" in impact["headline"].lower()


def test_biggest_wins_ranked_descending(tmp_path):
    wins = _impact(tmp_path, _inefficient_files())["biggest_wins"]
    saved = [w["bytes_saved"] for w in wins]
    assert saved == sorted(saved, reverse=True)
    assert wins  # non-empty


def test_determinism(tmp_path):
    a = _impact(tmp_path, _inefficient_files(), name="a.asar")
    b = _impact(tmp_path, _inefficient_files(), name="b.asar")
    assert a == b


def test_lean_app_fabricates_nothing(tmp_path):
    impact = _impact(tmp_path, _lean_files(), name="lean.asar")
    assert impact["lean"] is True
    assert impact["bytes_saved"] == 0
    assert impact["projected_bytes"] == impact["current_bytes"]
    assert impact["per_fix"] == []
    assert impact["biggest_wins"] == []
    assert "no significant" in impact["headline"].lower()
    assert str(impact["current_bytes"]) or impact["current_human"]  # size reported


def test_no_fabricated_runtime_metric_anywhere(tmp_path):
    """No *quantified* runtime/speed claim may ever appear. Directional, clearly-
    labelled wording ('generally faster … not measured') IS allowed — what is
    banned is a fabricated NUMBER: a speed percentage, an FPS count, a ms timing,
    an 'Nx faster'."""
    import re

    p = str(tmp_path / "x.asar")
    write_asar(p, _inefficient_files())
    r = scan(p, mode="efficiency", timestamp="T")
    blob = json.dumps(r.to_dict()).lower()

    # Literal fabricated-metric phrasings.
    for banned in ("% faster", "% smoother", "fps", "frames per second"):
        assert banned not in blob, f"fabricated runtime claim present: {banned!r}"
    # Numeric speed/timing patterns.
    for pat in (r"\d+\s*%\s*(faster|smoother|speed)",
                r"\d+\s*(ms|milliseconds)\b",
                r"\d+\s*x\s*faster",
                r"\d+\s*fps"):
        m = re.search(pat, blob)
        assert m is None, f"fabricated runtime metric {m.group(0)!r}"
    # Every percentage in the report is a size/payload figure, never speed.
    size_terms = ("payload", "size", "reduction", "minif", "compress",
                  "smaller", "codec")
    for m in re.finditer(r"[-−]?\d+(?:\.\d+)?\s*%", blob):
        ctx = blob[max(0, m.start() - 50): m.end() + 50]
        assert any(t in ctx for t in size_terms), \
            f"percentage not tied to size: …{ctx}…"
    assert r.impact_summary["disclaimer"]


def test_honesty_footer_present(tmp_path):
    impact = _impact(tmp_path, _inefficient_files())
    foot = impact["disclaimer"].lower()
    assert "does not run the app" in foot
    assert "profiling" in foot
