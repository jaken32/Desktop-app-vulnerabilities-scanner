"""Per-window / per-webview Electron configuration detection."""

import os

from deskscanner.checks.base import CheckContext
from deskscanner.checks.electron_config import ElectronConfigCheck
from deskscanner.models import AppInfo, Confidence, Severity
from deskscanner.unpack import load_asar
from helpers import write_asar


def _ctx(tmp_path, files):
    p = os.path.join(tmp_path, "a.asar")
    write_asar(p, {k: v.encode() for k, v in files.items()})
    bundle = load_asar(p)
    return CheckContext(bundle=bundle, app=AppInfo(name="t"))


def _run(tmp_path, files):
    return ElectronConfigCheck().run(_ctx(tmp_path, files))


def _by_key(findings, key):
    return [f for f in findings if f.source_locator.config_key == key]


def test_node_integration_plus_remote_is_critical(tmp_path):
    js = ("new BrowserWindow({webPreferences:{nodeIntegration:true}});"
          "win.loadURL('https://evil.example.com/x')")
    findings = _run(tmp_path, {"main.js": js})
    ni = _by_key(findings, "nodeIntegration")
    assert len(ni) == 1
    assert ni[0].severity is Severity.CRITICAL
    assert ni[0].confidence is Confidence.CONFIRMED


def test_node_integration_local_only_is_high(tmp_path):
    js = "new BrowserWindow({webPreferences:{nodeIntegration:true}}); win.loadFile('index.html')"
    ni = _by_key(_run(tmp_path, {"main.js": js}), "nodeIntegration")
    assert ni[0].severity is Severity.HIGH


def test_each_window_reported_independently(tmp_path):
    js = (
        "const a = new BrowserWindow({webPreferences:{contextIsolation:true}});\n"
        "const b = new BrowserWindow({webPreferences:{contextIsolation:false}});\n"
    )
    findings = _run(tmp_path, {"main.js": js})
    ci = _by_key(findings, "contextIsolation")
    # Only the insecure (false) window is flagged; the secure one is not.
    assert len(ci) == 1
    assert ci[0].source_locator.line == 2


def test_minified_lowers_confidence(tmp_path):
    js = "var x=" + "1;" * 50 + "new BrowserWindow({webPreferences:{contextIsolation:!1}});" + "y=2;" * 2000
    ci = _by_key(_run(tmp_path, {"app.min.js": js}), "contextIsolation")
    assert ci and ci[0].confidence is not Confidence.CONFIRMED


def test_webview_nodeintegration(tmp_path):
    html = "<html><head></head><body><webview src='x' nodeintegration></webview></body></html>"
    findings = _run(tmp_path, {"index.html": html})
    assert any(f.source_locator.config_key == "nodeintegration"
               and f.severity is Severity.HIGH for f in findings)


def test_missing_csp(tmp_path):
    html = "<html><head><title>x</title></head><body></body></html>"
    findings = _run(tmp_path, {"index.html": html})
    csp = [f for f in findings if "Content-Security-Policy" == f.source_locator.config_key]
    assert csp and csp[0].severity is Severity.MEDIUM


def test_present_csp_no_finding(tmp_path):
    html = ("<html><head><meta http-equiv=\"Content-Security-Policy\" "
            "content=\"default-src 'self'\"></head><body></body></html>")
    findings = _run(tmp_path, {"index.html": html})
    assert not any("Content-Security-Policy" == f.source_locator.config_key
                   and f.severity is Severity.MEDIUM for f in findings)


def test_weak_csp_flagged(tmp_path):
    html = ("<html><head><meta http-equiv=\"Content-Security-Policy\" "
            "content=\"default-src 'self'; script-src 'unsafe-inline'\"></head></html>")
    findings = _run(tmp_path, {"index.html": html})
    assert any("weak" in f.title.lower() for f in findings)


def test_open_external_literal_not_flagged(tmp_path):
    js = "shell.openExternal('https://safe.example.com')"
    findings = _run(tmp_path, {"main.js": js})
    assert not _by_key(findings, "shell.openExternal")


def test_open_external_variable_flagged_possible(tmp_path):
    js = "shell.openExternal(userControlledUrl)"
    f = _by_key(_run(tmp_path, {"main.js": js}), "shell.openExternal")
    assert f and f[0].confidence is Confidence.POSSIBLE
    assert f[0].false_positive_note


def test_context_bridge_broad_exposure(tmp_path):
    js = "contextBridge.exposeInMainWorld('api', ipcRenderer)"
    f = _by_key(_run(tmp_path, {"preload.js": js}), "exposeInMainWorld")
    assert f and f[0].severity is Severity.HIGH


def test_context_bridge_narrow_not_flagged(tmp_path):
    js = "contextBridge.exposeInMainWorld('api', { ping: () => ipcRenderer.invoke('p') })"
    assert not _by_key(_run(tmp_path, {"preload.js": js}), "exposeInMainWorld")


def test_every_finding_has_locator_and_confidence(tmp_path):
    js = "new BrowserWindow({webPreferences:{nodeIntegration:true, webSecurity:false}})"
    for f in _run(tmp_path, {"main.js": js}):
        assert f.source_locator.render()
        assert f.confidence in Confidence
        assert f.references
