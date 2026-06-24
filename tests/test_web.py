"""Web UI backend: routes, consent gate, error states."""

import os

import pytest

from helpers import write_insecure_asar

try:
    from fastapi.testclient import TestClient
    from deskscanner.web.app import app
    _CLIENT = TestClient(app)
except Exception:  # pragma: no cover - fastapi/starlette optional at runtime
    _CLIENT = None

pytestmark = pytest.mark.skipif(_CLIENT is None, reason="fastapi not available")


def test_healthz():
    assert _CLIENT.get("/healthz").json() == {"ok": True}


def test_index_served():
    r = _CLIENT.get("/")
    assert r.status_code == 200
    assert "scan-form" in r.text


def test_scan_requires_consent(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_insecure_asar(p)
    r = _CLIENT.post("/api/scan", json={"target": p, "consent": False})
    assert r.status_code == 400
    assert "Authorization" in r.json()["error"]


def test_scan_success(tmp_path):
    p = os.path.join(tmp_path, "app.asar")
    write_insecure_asar(p)
    r = _CLIENT.post("/api/scan", json={"target": p, "consent": True})
    assert r.status_code == 200
    data = r.json()
    assert data["grade"] == "F"
    assert len(data["findings"]) == 19
    assert data["html"].startswith("<!doctype html>")


def test_scan_non_electron_target_422(tmp_path):
    (tmp_path / "x.txt").write_text("nope")
    r = _CLIENT.post("/api/scan", json={"target": str(tmp_path), "consent": True})
    assert r.status_code == 422
    assert "error" in r.json()


def test_scan_empty_target_400():
    r = _CLIENT.post("/api/scan", json={"target": "  ", "consent": True})
    assert r.status_code == 400
