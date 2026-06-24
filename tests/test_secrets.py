"""Secret scanning: detection, redaction, placeholder filtering, entropy."""

import os

from deskscanner.checks.base import CheckContext
from deskscanner.checks.secrets import SecretsCheck, shannon_entropy
from deskscanner.models import AppInfo, Confidence, Severity
from deskscanner.unpack import load_asar
from helpers import write_asar


def _run(tmp_path, files):
    p = os.path.join(tmp_path, "a.asar")
    write_asar(p, {k: v.encode() for k, v in files.items()})
    ctx = CheckContext(bundle=load_asar(p), app=AppInfo(name="t"))
    return SecretsCheck().run(ctx)


def test_detects_aws_key_id(tmp_path):
    key = "AK" + "IA" + "J5Z3QO2K" + "7NJ4XR9P"
    findings = _run(tmp_path, {"c.json": f'{{"k":"{key}"}}'})
    aws = [f for f in findings if "AWS Access Key ID" in f.title]
    assert aws and aws[0].severity is Severity.CRITICAL
    # Redacted: the full secret must not appear in evidence.
    assert key not in aws[0].evidence
    assert "…" in aws[0].evidence


def test_detects_private_key(tmp_path):
    pk = "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
    findings = _run(tmp_path, {"k.pem": pk})
    assert any("Private key" in f.title and f.severity is Severity.CRITICAL
               for f in findings)


def test_placeholder_filtered(tmp_path):
    findings = _run(tmp_path, {"c.json": '{"api_key":"YOUR_API_KEY_HERE"}'})
    assert not [f for f in findings if "Generic" in f.title or "entropy" in f.title.lower()]


def test_example_value_filtered(tmp_path):
    # AKIA...EXAMPLE is the canonical AWS docs placeholder -> filtered.
    findings = _run(tmp_path, {"c.json": '{"k":"AKIAIOSFODNN7EXAMPLE"}'})
    assert not any("AWS" in f.title for f in findings)


def test_generic_assigned_secret_possible(tmp_path):
    findings = _run(tmp_path, {"c.json": '{"client_secret":"swh4kqp2mfn8dlx0"}'})
    g = [f for f in findings if "Generic" in f.title]
    assert g and g[0].confidence is Confidence.POSSIBLE
    assert g[0].false_positive_note


def test_entropy_only_is_low_confidence(tmp_path):
    token = "Zx9Kq2Lm8Wp4Tn6Rb1Vy7Hc3Jd5Gf0As"
    findings = _run(tmp_path, {"app.js": f'const t = "{token}"'})
    ent = [f for f in findings if "entropy" in f.title.lower()]
    assert ent and ent[0].confidence is Confidence.POSSIBLE


def test_integrity_hash_not_flagged(tmp_path):
    # lockfile integrity hashes must not be reported as secrets.
    findings = _run(tmp_path, {"package-lock.json":
                               '{"integrity":"sha512-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789=="}'})
    assert findings == []


def test_shannon_entropy_math():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.9
