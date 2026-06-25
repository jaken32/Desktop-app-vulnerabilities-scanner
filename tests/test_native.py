"""Native / Flutter engine tests — offline, deterministic, no macOS required.

macOS tool output (codesign/spctl/stapler) is injected as captured strings so
the parsing + findings are verified without those tools. Synthetic ``.app``
directories provide the on-disk artifacts (Info.plist, frameworks, storage).
"""

import os
import plistlib
import stat

import pytest

from deskscanner.engine import scan
from deskscanner.models import Severity
from deskscanner.native.detect import detect_engine
from deskscanner.native.engine import run_native
from deskscanner.native import probe as probe_mod
from deskscanner.native.context import SafeFS
from deskscanner.reporting.html import render_html
from deskscanner.unpack import UnsafePathError

# Captured-style codesign output.
CS_ADHOC = ("Executable=/x/App\nIdentifier=com.example.app\n"
            "CodeDirectory v=20400 size=1 flags=0x2(adhoc) hashes=1\nSignature=adhoc\n")
CS_SIGNED_HARDENED = (
    "Executable=/x/App\nIdentifier=com.example.app\n"
    "CodeDirectory v=20500 size=1 flags=0x10000(runtime) hashes=1\n"
    "Authority=Developer ID Application: Example Inc (TEAMID123)\n"
    "Authority=Developer ID Certification Authority\nTeamIdentifier=TEAMID123\n")
CS_UNSIGNED = "code object is not signed at all\n"

ENTS_DANGEROUS = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.get-task-allow</key><true/>
<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>"""
ENTS_SANDBOXED = """<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
</dict></plist>"""


def _make_app(tmp_path, name, info, *, flutter=True, storage=None,
              storage_mode=0o600, resources=None):
    app = tmp_path / name
    (app / "Contents" / "MacOS").mkdir(parents=True)
    if flutter:
        (app / "Contents" / "Frameworks" / "FlutterMacOS.framework").mkdir(parents=True)
        (app / "Contents" / "Frameworks" / "App.framework").mkdir(parents=True)
    (app / "Contents" / "Resources").mkdir(parents=True, exist_ok=True)
    plistlib.dump(info, open(app / "Contents" / "Info.plist", "wb"))
    (app / "Contents" / "MacOS" / name.replace(".app", "")).write_bytes(
        b"\xcf\xfa\xed\xfe placeholder mach-o")
    for rel, content in (resources or {}).items():
        p = app / "Contents" / "Resources" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    storage_dir = None
    if storage:
        storage_dir = tmp_path / (name + ".data")
        storage_dir.mkdir()
        for rel, content in storage.items():
            p = storage_dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            os.chmod(p, storage_mode)
    return str(app), ([str(storage_dir)] if storage_dir else None)


def _insecure(tmp_path):
    info = {
        "CFBundleName": "Insecure", "CFBundleShortVersionString": "1.0.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["insecureapp"]}],
        "NSCameraUsageDescription": "",
        "SUFeedURL": "http://updates.example.com/appcast.xml",
    }
    app, storage = _make_app(
        tmp_path, "Insecure.app", info, flutter=True,
        storage={"token.json": '{"access_token":"eyJhbGciOiJ.IUzI1NiIsInR.abcDEFghIJ"}'},
        storage_mode=0o644)
    return run_native(
        detect_engine(app), storage_paths=storage,
        codesign_text=CS_ADHOC, entitlements_text=ENTS_DANGEROUS,
        spctl_result=(3, "Insecure.app: rejected\nsource=no usable signature"),
        stapler_rc=1, _run_tools=False, timestamp="T")


def _secure(tmp_path):
    info = {
        "CFBundleName": "Secure", "CFBundleShortVersionString": "2.0.0",
        "SUFeedURL": "https://updates.example.com/appcast.xml",
        "SUPublicEDKey": "abc123EdDSAkey==",
    }
    app, storage = _make_app(
        tmp_path, "Secure.app", info, flutter=True,
        storage={"prefs.json": '{"theme":"dark"}'}, storage_mode=0o600,
        resources={"config.json": '{"endpoint":"https://api.example.com"}'})
    return run_native(
        detect_engine(app), storage_paths=storage,
        codesign_text=CS_SIGNED_HARDENED, entitlements_text=ENTS_SANDBOXED,
        spctl_result=(0, "Secure.app: accepted\nsource=Notarized Developer ID"),
        stapler_rc=0, _run_tools=False, timestamp="T")


def _discs(result):
    return {f.discriminator for f in result.findings}


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #
def test_routing_flutter(tmp_path):
    app, _ = _make_app(tmp_path, "F.app", {"CFBundleName": "F"}, flutter=True)
    det = detect_engine(app)
    assert det.engine == "flutter"
    assert "FlutterMacOS.framework" in det.reason


def test_routing_native_generic(tmp_path):
    app, _ = _make_app(tmp_path, "N.app", {"CFBundleName": "N"}, flutter=False)
    det = detect_engine(app)
    assert det.engine == "native"
    assert "Info.plist" in det.reason


def test_routing_electron_asar(tmp_path):
    app = tmp_path / "E.app"
    (app / "Contents" / "Resources").mkdir(parents=True)
    (app / "Contents" / "Resources" / "app.asar").write_bytes(b"\x00\x00\x00\x04")
    det = detect_engine(str(app))
    assert det.engine == "electron"


def test_routing_override(tmp_path):
    app, _ = _make_app(tmp_path, "F.app", {"CFBundleName": "F"}, flutter=True)
    assert detect_engine(app, override="native").engine == "native"


def test_routing_unknown(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    assert detect_engine(str(d)).engine == "unknown"


def test_engine_recorded_on_result(tmp_path):
    r = _insecure(tmp_path)
    assert r.engine == "flutter"
    assert "FlutterMacOS.framework" in r.engine_reason


# --------------------------------------------------------------------------- #
# Insecure vs secure fixtures (the grade gate)
# --------------------------------------------------------------------------- #
def test_insecure_fixture_grades_poorly_with_expected_findings(tmp_path):
    r = _insecure(tmp_path)
    assert r.grade in ("D", "F")
    d = _discs(r)
    assert "signing:adhoc" in d
    assert "hardened-runtime:absent" in d
    assert "entitlements:com.apple.security.get-task-allow" in d           # CRITICAL
    assert "entitlements:com.apple.security.cs.disable-library-validation" in d
    assert "sandbox:absent" in d
    assert "info-plist:ats" in d
    assert "info-plist:url-schemes" in d
    assert "update:http-feed" in d
    assert any(x.startswith("storage:secret") for x in d)
    assert any(x.startswith("storage:perm") for x in d)
    # get-task-allow must be CRITICAL.
    gta = [f for f in r.findings
           if f.discriminator == "entitlements:com.apple.security.get-task-allow"][0]
    assert gta.severity is Severity.CRITICAL


def test_secure_fixture_grades_A_with_no_high(tmp_path):
    r = _secure(tmp_path)
    assert r.grade == "A"
    highs = [f for f in r.findings
             if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    assert highs == [], [f.title for f in highs]


def test_no_electron_findings_for_flutter(tmp_path):
    r = _insecure(tmp_path)
    blob = " ".join(f.title.lower() + " " + f.evidence.lower() for f in r.findings)
    for banned in ("nodeintegration", "contextisolation", "webpreferences",
                   "csp", "preload"):
        # the only mention allowed is the explicit "not applicable" scope note
        scope = [f for f in r.findings if f.discriminator == "scope:electron-na"]
        assert scope, "expected the Electron-not-applicable scope note"
        others = " ".join(f.title.lower() + " " + f.evidence.lower()
                          for f in r.findings if f.discriminator != "scope:electron-na")
        assert banned not in others, f"fabricated electron finding: {banned}"


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #
def test_unsigned_is_critical(tmp_path):
    app, _ = _make_app(tmp_path, "U.app", {"CFBundleName": "U"})
    r = run_native(detect_engine(app), codesign_text=CS_UNSIGNED,
                   entitlements_text="", spctl_result=(3, "rejected"),
                   stapler_rc=1, _run_tools=False, timestamp="T")
    f = [x for x in r.findings if x.discriminator == "signing:unsigned"]
    assert f and f[0].severity is Severity.CRITICAL


def test_tools_unavailable_marks_not_assessed(tmp_path):
    app, _ = _make_app(tmp_path, "X.app", {"CFBundleName": "X"})
    # No injected tool output and _run_tools False -> everything unavailable.
    r = run_native(detect_engine(app), _run_tools=False, timestamp="T")
    d = _discs(r)
    assert "signing:not-assessed" in d
    assert any("not assessed" in f.evidence.lower() for f in r.findings)


# --------------------------------------------------------------------------- #
# Path-traversal / symlink-escape guard
# --------------------------------------------------------------------------- #
def test_safefs_refuses_traversal(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("nope")
    fs = SafeFS([str(root)])
    with pytest.raises(UnsafePathError):
        fs.resolve(str(root / ".." / "secret.txt"))


def test_safefs_refuses_symlink_escape(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = root / "link.txt"
    try:
        os.symlink(str(outside), str(link))
    except OSError:
        pytest.skip("symlinks not supported here")
    with pytest.raises(UnsafePathError):
        fs = SafeFS([str(root)])
        fs.read_bytes(str(link))


# --------------------------------------------------------------------------- #
# Loopback-only enforcement
# --------------------------------------------------------------------------- #
def test_assert_loopback_refuses_non_loopback():
    probe_mod.assert_loopback("127.0.0.1")  # ok
    probe_mod.assert_loopback("::1")        # ok
    for bad in ("10.0.0.1", "8.8.8.8", "example.com", "0.0.0.0", "169.254.1.1"):
        with pytest.raises(probe_mod.LoopbackViolation):
            probe_mod.assert_loopback(bad)


def test_default_getter_refuses_non_loopback_url():
    with pytest.raises(probe_mod.LoopbackViolation):
        probe_mod._default_getter("http://example.com/", "GET")


def test_probe_finds_permissive_cors(tmp_path):
    app, _ = _make_app(tmp_path, "P.app", {"CFBundleName": "P"})
    ctx_result = run_native  # placeholder to keep flake8 quiet
    from deskscanner.native.context import build_native_context
    ctx = build_native_context(app, engine="flutter", _run_tools=False)

    def fake_getter(url, method):
        assert url.startswith("http://127.0.0.1:")  # never anything else
        return 200, {"access-control-allow-origin": "*",
                     "access-control-allow-credentials": "true",
                     "server": "FlutterServer/1.0"}, "{}"

    findings = probe_mod.probe(ctx, ports=[39300], getter=fake_getter)
    discs = {f.discriminator for f in findings}
    assert any(x.startswith("local-api:cors") for x in discs)
    assert any(x.startswith("local-api:noauth") for x in discs)
    assert all(f.volatile for f in findings)


def test_prospect_lists_ports_without_request(tmp_path):
    app, _ = _make_app(tmp_path, "P.app", {"CFBundleName": "P"})
    from deskscanner.native.context import build_native_context
    ctx = build_native_context(app, engine="flutter", _run_tools=False)
    findings = probe_mod.prospect(ctx, discover=lambda: [39300, 8080])
    assert any("39300" in f.evidence for f in findings)


# --------------------------------------------------------------------------- #
# XSS-safe reporting
# --------------------------------------------------------------------------- #
def test_html_escapes_hostile_evidence(tmp_path):
    info = {"CFBundleName": "Evil",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["x<script>alert(1)</script>"]}]}
    app, _ = _make_app(tmp_path, "Evil.app", info, flutter=True)
    r = run_native(detect_engine(app), codesign_text=CS_SIGNED_HARDENED,
                   entitlements_text=ENTS_SANDBOXED, spctl_result=(0, "accepted"),
                   stapler_rc=0, _run_tools=False, timestamp="T")
    html = render_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #
def test_determinism(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = _insecure(tmp_path / "a").to_dict()
    b = _insecure(tmp_path / "b").to_dict()
    # timestamps are fixed ("T"); everything else must match exactly.
    assert [f["stable_id"] for f in a["findings"]] == [f["stable_id"] for f in b["findings"]]
    assert a["grade"] == b["grade"]
    assert a["findings"] == b["findings"]


def test_scan_router_end_to_end(tmp_path):
    """The top-level scan() routes a Flutter bundle to the native engine."""
    app, storage = _make_app(tmp_path, "Rt.app", {"CFBundleName": "Rt"}, flutter=True)
    r = scan(app, timestamp="T")  # default mode; native target
    assert r.engine == "flutter"
