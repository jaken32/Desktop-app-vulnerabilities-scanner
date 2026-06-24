"""The AI analysis layer is optional and network-isolated in tests: we inject a
fake client so no real API call is made, and verify parsing + error handling."""

import json

import pytest

from deskscanner.models import (
    AppInfo,
    Confidence,
    Finding,
    Remediation,
    ScanResult,
    Severity,
    SourceLocator,
)
from deskscanner.reporting.analysis import (
    Analysis,
    AnalysisError,
    generate_analysis,
)


def _result():
    f = Finding(
        title="nodeIntegration enabled",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        category="electron",
        evidence="nodeIntegration: true",
        source_locator=SourceLocator("main.js", line=5),
        remediation=Remediation("Disable it."),
    )
    return ScanResult(app=AppInfo(name="X", version="1.0"), findings=[f],
                      scan_timestamp="T", grade="D", score=40.0)


class _Block:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text, model="claude-opus-4-8"):
        self.content = [_Block(text)]
        self.model = model


class _FakeMessages:
    def __init__(self, payload, record):
        self._payload = payload
        self._record = record

    def create(self, **kwargs):
        self._record.update(kwargs)
        return _Resp(json.dumps(self._payload))


class _FakeClient:
    def __init__(self, payload, record):
        self.messages = _FakeMessages(payload, record)


def test_generate_analysis_parses_structured_output():
    payload = {
        "plain_english": "Plain words.",
        "in_depth": "Technical words referencing main.js.",
        "key_risks": ["risk one", "risk two"],
        "recommendations": ["do this", "then that"],
    }
    record: dict = {}
    out = generate_analysis(_result(), client=_FakeClient(payload, record))

    assert isinstance(out, Analysis)
    assert out.plain_english == "Plain words."
    assert out.key_risks == ["risk one", "risk two"]
    assert out.recommendations == ["do this", "then that"]
    assert out.model == "claude-opus-4-8"
    # It must request structured JSON output and send the scan as the prompt.
    assert record["model"] == "claude-opus-4-8"
    assert record["output_config"]["format"]["type"] == "json_schema"
    assert "json" in record["messages"][0]["content"].lower()


def test_missing_api_key_raises_clear_error(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AnalysisError) as exc:
        generate_analysis(_result())
    assert "ANTHROPIC_API_KEY" in str(exc.value)


def test_api_failure_is_wrapped(monkeypatch):
    class _BoomMessages:
        def create(self, **kwargs):
            raise RuntimeError("boom")

    class _BoomClient:
        messages = _BoomMessages()

    with pytest.raises(AnalysisError) as exc:
        generate_analysis(_result(), client=_BoomClient())
    assert "failed" in str(exc.value).lower()


def test_invalid_json_is_wrapped():
    class _BadMessages:
        def create(self, **kwargs):
            return _Resp("not json at all")

    class _BadClient:
        messages = _BadMessages()

    with pytest.raises(AnalysisError):
        generate_analysis(_result(), client=_BadClient())
