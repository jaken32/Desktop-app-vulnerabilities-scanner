"""Local API probe: loopback-only, read-only, timeout-bounded, volatile output.

A throwaway HTTP server is started on 127.0.0.1 so the probe has something safe
and local to talk to. It reflects the Origin header (to exercise CORS detection)
and omits security headers.
"""

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from deskscanner.checks.base import CheckContext
from deskscanner.checks.local_api import LocalApiCheck, _is_loopback
from deskscanner.models import AppInfo, Severity
from deskscanner.unpack import load_asar
from helpers import write_asar


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _respond(self):
        origin = self.headers.get("Origin")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if origin:  # reflect arbitrary origin -> permissive CORS
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","data":[1,2,3]}')

    def do_GET(self):
        self._respond()

    def do_OPTIONS(self):
        self._respond()


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield port
    server.shutdown()


def _ctx(tmp_path, source, probe=True, timeout=4.0):
    p = os.path.join(tmp_path, "a.asar")
    write_asar(p, {"main.js": source.encode()})
    return CheckContext(bundle=load_asar(p), app=AppInfo(name="t"),
                        probe_enabled=probe, probe_timeout=timeout)


def test_is_loopback():
    assert _is_loopback("127.0.0.1")
    assert _is_loopback("::1")
    assert _is_loopback("[::1]")
    assert not _is_loopback("0.0.0.0")
    assert not _is_loopback("8.8.8.8")


def test_static_bind_all_detected(tmp_path):
    src = "server.listen(3000, '0.0.0.0')"
    findings = LocalApiCheck().run(_ctx(tmp_path, src, probe=False))
    bind = [f for f in findings if "0.0.0.0" in f.title]
    assert bind and bind[0].severity is Severity.MEDIUM
    assert not bind[0].volatile  # static finding


def test_probe_finds_cors_and_headers(tmp_path, local_server):
    src = f"app.listen({local_server}, '127.0.0.1')"
    findings = LocalApiCheck().run(_ctx(tmp_path, src))
    cors = [f for f in findings if "CORS" in f.title]
    assert cors and cors[0].volatile
    headers = [f for f in findings if "missing security header" in f.title]
    assert headers and all(h.volatile for h in headers)
    noauth = [f for f in findings if "without authentication" in f.title]
    assert noauth and noauth[0].volatile


def test_probe_disabled_no_volatile(tmp_path, local_server):
    src = f"app.listen({local_server}, '127.0.0.1')"
    findings = LocalApiCheck().run(_ctx(tmp_path, src, probe=False))
    assert not any(f.volatile for f in findings)


def test_probe_unreachable_is_graceful(tmp_path):
    # A detected-but-closed port must not crash or hang.
    src = "app.listen(1, '127.0.0.1')"  # port 1: nothing listening
    ctx = _ctx(tmp_path, src, timeout=1.0)
    findings = LocalApiCheck().run(ctx)
    assert isinstance(findings, list)
    assert any("no loopback service responded" in n for n in ctx.notes)
