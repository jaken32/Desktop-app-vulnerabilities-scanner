"""AI-written analysis of a scan result, via the Anthropic Claude API.

The deterministic scanner produces structured findings; this module turns those
findings into human-facing narrative: a plain-English explanation a non-expert
can follow, and a deeper technical analysis. It is *optional* — the scanner runs
and reports without it — and only activates when the caller asks for analysis
and an ``ANTHROPIC_API_KEY`` is available.

The model is asked to interpret and explain ONLY the findings the scanner
actually produced (it is told not to invent issues), so the narrative stays
anchored to the deterministic evidence.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import ScanResult

MODEL = "claude-opus-4-8"

_SYSTEM = """\
You are a senior application-security analyst. You are given the structured \
output of a static security scan of an Electron desktop application. Your job \
is to interpret and explain the findings the scanner produced — nothing more.

Rules:
- Ground every statement in the findings provided. Do NOT invent vulnerabilities, \
CVEs, or evidence that is not in the scan data.
- Respect the scanner's own severity and confidence: a "possible" finding is not \
a confirmed breach. Reflect that uncertainty honestly.
- The scan is static analysis plus a safe loopback probe only. A good grade means \
the inspected configuration looks sound for the checks run — not that the app is \
secure overall. Never overstate what the scan proves.
- Be specific and practical. Prefer concrete file/config references from the data \
over generic advice.\
"""

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "plain_english": {
            "type": "string",
            "description": "A clear explanation for a non-technical reader: what "
                           "was scanned, what the grade means, and what the most "
                           "important issues are in everyday language. 2-4 short "
                           "paragraphs.",
        },
        "in_depth": {
            "type": "string",
            "description": "A technical analysis for an engineer: how the findings "
                           "relate, the realistic attack surface they imply, and "
                           "the order in which to address them. Reference specific "
                           "findings, files, and config keys from the scan.",
        },
        "key_risks": {
            "type": "array",
            "items": {"type": "string"},
            "description": "The most important risks, worst first, one sentence each.",
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Concrete, prioritised next steps, one per item.",
        },
    },
    "required": ["plain_english", "in_depth", "key_risks", "recommendations"],
    "additionalProperties": False,
}


class AnalysisError(Exception):
    """Raised when the AI analysis cannot be produced (missing key/SDK, API error)."""


@dataclass
class Analysis:
    """The AI-written narrative layer over a scan result."""

    plain_english: str
    in_depth: str
    key_risks: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    model: str = MODEL

    def to_dict(self) -> dict[str, Any]:
        return {
            "plain_english": self.plain_english,
            "in_depth": self.in_depth,
            "key_risks": list(self.key_risks),
            "recommendations": list(self.recommendations),
            "model": self.model,
        }


def _build_prompt(result: ScanResult) -> str:
    """Compact, deterministic JSON view of the scan for the model to explain."""
    data = result.to_dict()
    return (
        "Here is the scan result as JSON. Interpret and explain it per your "
        "instructions.\n\n```json\n"
        + json.dumps(data, indent=2, sort_keys=False)
        + "\n```"
    )


def generate_analysis(
    result: ScanResult,
    *,
    client: Any = None,
    model: str = MODEL,
    api_key: Optional[str] = None,
    effort: str = "medium",
) -> Analysis:
    """Produce an :class:`Analysis` for ``result`` using Claude.

    ``client`` may be injected (for testing); otherwise an ``anthropic.Anthropic``
    client is created from ``api_key`` or the ``ANTHROPIC_API_KEY`` environment
    variable. Raises :class:`AnalysisError` on any failure so callers can fall
    back to a report without the narrative.
    """
    if client is None:
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise AnalysisError(
                "AI analysis needs an Anthropic API key. Set ANTHROPIC_API_KEY "
                "or run without --analyze."
            )
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise AnalysisError(
                "The 'anthropic' package is required for --analyze. Install the "
                "report extra: pip install -e \".[report]\""
            ) from exc
        client = anthropic.Anthropic(api_key=key)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=8000,
            system=_SYSTEM,
            output_config={"format": {"type": "json_schema", "schema": _SCHEMA},
                           "effort": effort},
            messages=[{"role": "user", "content": _build_prompt(result)}],
        )
    except Exception as exc:  # noqa: BLE001 - surface any SDK/API error uniformly
        raise AnalysisError(f"AI analysis request failed: {exc}") from exc

    text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), "")
    if not text:
        raise AnalysisError("AI analysis returned no content.")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"AI analysis returned invalid JSON: {exc}") from exc

    return Analysis(
        plain_english=str(payload.get("plain_english", "")).strip(),
        in_depth=str(payload.get("in_depth", "")).strip(),
        key_risks=[str(x) for x in payload.get("key_risks", [])],
        recommendations=[str(x) for x in payload.get("recommendations", [])],
        model=getattr(response, "model", model),
    )
