"""Scan orchestrator: locate -> context -> run checks -> score -> ScanResult.

The engine is deliberately thin. It computes app metadata, builds the shared
:class:`CheckContext`, runs every registered check in fixed order, then sorts
and scores the findings. Determinism lives here: given the same bundle, the
static findings and grade are identical (the timestamp and live-probe results
are the only volatile outputs).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, Optional

from .checks import build_checks
from .checks.base import CheckContext
from .checks.efficiency import analyze as analyze_efficiency
from .locate import Located, TargetNotElectronError, locate
from .models import AppInfo, ScanResult
from .native.detect import detect_engine
from .native.engine import run_native
from .scoring import apply_efficiency_score, apply_score, sort_findings
from .unpack import UnpackLimits


ProgressFn = Callable[[str, int, int], None]
MODES = ("security", "efficiency", "all")


def _app_info_from_bundle(ctx_bundle, located: Located) -> AppInfo:
    name = located.app_name_hint
    version = "unknown"
    pkg = ctx_bundle.get("package.json")
    if pkg:
        try:
            data = json.loads(pkg.read_text())
            name = data.get("productName") or data.get("name") or name
            version = str(data.get("version") or version)
        except Exception:
            pass
    return AppInfo(
        name=str(name),
        version=version,
        bundle_path=located.asar_path or located.bundle.source_path,
        is_electron=True,
    )


def _minified_ratio(ctx: CheckContext) -> float:
    js = [f for f in ctx.bundle.files
          if f.relpath.endswith((".js", ".mjs", ".cjs"))]
    if not js:
        return 0.0
    minified = sum(1 for f in js if ctx.file_is_minified(f))
    return minified / len(js)


def scan(
    target: str,
    *,
    mode: str = "security",
    engine: Optional[str] = None,
    probe: bool = False,
    prospect: bool = False,
    probe_timeout: float = 4.0,
    limits: Optional[UnpackLimits] = None,
    storage_paths: Optional[list[str]] = None,
    timestamp: Optional[str] = None,
    progress: Optional[ProgressFn] = None,
) -> ScanResult:
    """Run a scan and return a :class:`ScanResult`.

    A platform router inspects the target and picks an engine:
      * an Electron ``app.asar`` -> the existing Electron engine (``mode`` applies).
      * ``Contents/Frameworks/FlutterMacOS.framework`` -> the Flutter engine.
      * otherwise a valid ``.app`` -> the generic native engine.
    ``engine`` ("electron"|"flutter"|"native") forces the choice.

    ``mode`` (Electron only) selects the analysis axes: ``"security"`` (default),
    ``"efficiency"``, or ``"all"``. Native targets are security-only.

    Raises :class:`~deskscanner.locate.TargetNotElectronError` when the target is
    not a recognised desktop app bundle.
    """
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")

    detection = detect_engine(target, override=engine)
    if detection.engine == "unknown":
        raise TargetNotElectronError(detection.reason)
    if detection.engine in ("flutter", "native"):
        return run_native(
            detection, probe=probe, prospect=prospect,
            storage_paths=storage_paths, timestamp=timestamp, progress=progress)

    # --- Electron engine (unchanged) ------------------------------------- #
    limits = limits or UnpackLimits.from_env()
    located = locate(target, limits)
    app = _app_info_from_bundle(located.bundle, located)

    ctx = CheckContext(
        bundle=located.bundle,
        app=app,
        resources_dir=located.resources_dir,
        asar_path=located.asar_path,
        probe_enabled=probe,
        probe_timeout=probe_timeout,
        storage_paths=storage_paths or [],
    )

    app.minified_ratio = _minified_ratio(ctx)

    result = ScanResult(
        app=app,
        mode=mode,
        scan_timestamp=timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        probe_attempted=probe,
    )

    if mode in ("security", "all"):
        checks = build_checks()
        all_findings = []
        for i, check in enumerate(checks):
            if progress:
                progress(check.name, i, len(checks))
            all_findings.extend(check.run(ctx))
        findings = sort_findings(all_findings)
        result.findings = findings
        result.probe_reachable = any(f.volatile for f in findings)
        result.notes = list(ctx.notes)
        apply_score(result)
    else:
        result.grade = "N/A"

    if mode in ("efficiency", "all"):
        if progress:
            progress("efficiency", 0, 1)
        eff = analyze_efficiency(ctx)
        result.efficiency_findings = sort_findings(eff.findings)
        result.size_summary = eff.size_summary
        result.impact_summary = eff.impact_summary
        apply_efficiency_score(result)

    if progress:
        progress("scoring", 1, 1)
    return result


__all__ = ["scan", "TargetNotElectronError"]
