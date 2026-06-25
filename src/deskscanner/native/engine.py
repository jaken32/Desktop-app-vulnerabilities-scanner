"""Native / Flutter engine — build context, run checks, score, emit ScanResult.

Shares the Finding schema, scoring, deterministic sort, and report renderer with
the Electron engine. The only difference is *which* checks run.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from ..models import AppInfo, Confidence, Finding, Remediation, ScanResult, \
    Severity, SourceLocator
from ..scoring import apply_score, sort_findings
from . import macos
from .checks import NATIVE_CHECKS
from .context import build_native_context
from .detect import EngineDetection
from . import probe as probe_mod

ProgressFn = Callable[[str, int, int], None]


def _not_applicable_note(engine: str) -> Finding:
    return Finding(
        title="Web/Electron renderer checks are not applicable",
        severity=Severity.INFO, confidence=Confidence.CONFIRMED,
        category="scope",
        evidence=(f"This is a {engine} app with no app.asar and no embedded web "
                  "renderer, so Electron-specific checks (nodeIntegration, "
                  "contextIsolation, CSP-in-renderer, webPreferences, preload "
                  "exposure) do not exist here and are not reported."),
        source_locator=SourceLocator("<native>"),
        remediation=Remediation("No action — scope clarification."),
        why_it_matters="Credibility: the tool does not fabricate Electron findings "
                       "for a native target.",
        discriminator="scope:electron-na")


def run_native(
    detection: EngineDetection,
    *,
    probe: bool = False,
    prospect: bool = False,
    storage_paths: Optional[list] = None,
    runner: macos.Runner = macos.default_runner,
    timestamp: Optional[str] = None,
    progress: Optional[ProgressFn] = None,
    # test injection — forwarded to build_native_context
    **ctx_overrides,
) -> ScanResult:
    engine = detection.engine
    ctx = build_native_context(
        detection.app_path, engine=engine, runner=runner,
        storage_paths=storage_paths, probe_enabled=probe, prospect=prospect,
        **ctx_overrides)

    findings: list = [_not_applicable_note(engine)]
    total = len(NATIVE_CHECKS) + (1 if (probe or prospect) else 0)
    for i, check in enumerate(NATIVE_CHECKS):
        if progress:
            progress(check.__name__.replace("check_", ""), i, total)
        findings.extend(check(ctx))

    if prospect and not probe:
        if progress:
            progress("loopback prospect", len(NATIVE_CHECKS), total)
        findings.extend(probe_mod.prospect(ctx))
    elif probe:
        if progress:
            progress("loopback probe", len(NATIVE_CHECKS), total)
        findings.extend(probe_mod.probe(ctx))

    findings = sort_findings(findings)

    app = AppInfo(
        name=ctx.name, version=ctx.version, bundle_path=ctx.app_path,
        is_electron=False,
        code_signed=(ctx.codesign.get("signed") if ctx.codesign.get("available") else None),
        code_sign_note=("; ".join(ctx.codesign.get("authorities") or [])
                        if ctx.codesign.get("available") else "not assessed on this host"),
    )

    result = ScanResult(
        app=app,
        findings=findings,
        engine=engine,
        engine_reason=detection.reason + (f" ({detection.artifact})"
                                          if detection.artifact else ""),
        mode="security",
        scan_timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        probe_attempted=probe,
        probe_reachable=any(f.volatile and "none" not in f.discriminator
                            for f in findings),
        notes=list(ctx.notes),
    )
    apply_score(result)
    return result
