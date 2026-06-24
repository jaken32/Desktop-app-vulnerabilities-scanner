"""deskscanner command-line interface.

Subcommands:
  scan TARGET   Statically scan an installed Electron app (+ optional safe
                loopback probe) and print a graded report.
  serve         Launch the local web UI.

A consent gate runs before any scan: the user must confirm they are authorised
to analyse the target (skippable with --yes / DESKSCANNER_ASSUME_YES=1).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .diff import diff_reports
from .engine import scan
from .locate import TargetNotElectronError
from .reporting.cli import render_cli
from .reporting.html import render_html
from .unpack import UnpackError, UnpackLimits

_CONSENT = """\
AUTHORIZATION NOTICE
--------------------
deskscanner performs STATIC analysis of an installed Electron application and,
only if you pass --probe, a SAFE read-only request to the app's own loopback
service (127.0.0.1). It never modifies the target, never reverse-engineers
native binaries, and never touches remote or non-loopback hosts.

Only scan software you own or are explicitly authorised to assess.
"""


def _confirm(assume_yes: bool) -> bool:
    if assume_yes or os.environ.get("DESKSCANNER_ASSUME_YES") == "1":
        return True
    print(_CONSENT)
    try:
        ans = input("Type 'yes' to confirm you are authorised to scan: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans in ("y", "yes")


def _progress(name: str, i: int, total: int) -> None:
    print(f"  [{i + 1}/{total}] {name}…", file=sys.stderr)


def _cmd_scan(args) -> int:
    if not _confirm(args.yes):
        print("Aborted: authorization not confirmed.", file=sys.stderr)
        return 2

    try:
        result = scan(
            args.target,
            mode=getattr(args, "mode", "security"),
            probe=getattr(args, "probe", False),
            probe_timeout=getattr(args, "probe_timeout", 4.0),
            limits=UnpackLimits.from_env(),
            storage_paths=getattr(args, "storage_path", None) or [],
            progress=None if args.quiet else _progress,
        )
    except TargetNotElectronError as exc:
        print(f"\nNot an Electron target: {exc}", file=sys.stderr)
        return 3
    except UnpackError as exc:
        print(f"\nCould not safely read the bundle: {exc}", file=sys.stderr)
        return 4
    except FileNotFoundError as exc:
        print(f"\nFile not found: {exc}", file=sys.stderr)
        return 3

    diff = None
    if getattr(args, "diff", None):
        try:
            with open(args.diff, "r", encoding="utf-8") as fp:
                previous = json.load(fp)
            diff = diff_reports(previous, result)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"Could not read --diff baseline ({exc}); continuing without diff.",
                  file=sys.stderr)

    # Optional AI narrative (used by stdout, PDF, and the JSON report).
    analysis = None
    if getattr(args, "analyze", False):
        from .reporting.analysis import AnalysisError, generate_analysis
        try:
            analysis = generate_analysis(result)
        except AnalysisError as exc:
            print(f"AI analysis unavailable ({exc}); continuing without it.",
                  file=sys.stderr)

    if args.json:
        payload = result.to_dict()
        if analysis is not None:
            payload["analysis"] = analysis.to_dict()
        with open(args.json, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, sort_keys=False)
        print(f"Wrote JSON report to {args.json}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fp:
            fp.write(render_html(result, diff=diff))
        print(f"Wrote HTML report to {args.html}", file=sys.stderr)
    if args.pdf:
        from .reporting.pdf import write_pdf
        write_pdf(result, args.pdf, analysis=analysis)
        print(f"Wrote PDF report to {args.pdf}", file=sys.stderr)

    if args.format == "json" and not args.json:
        payload = result.to_dict()
        if analysis is not None:
            payload["analysis"] = analysis.to_dict()
        json.dump(payload, sys.stdout, indent=2)
        print()
    elif args.format != "json":
        render_cli(result, diff=diff)
        if analysis is not None:
            _print_analysis(analysis)

    # Exit non-zero if there are confirmed high/critical findings on either axis
    # (CI-friendly).
    severe = [f for f in (result.findings + result.efficiency_findings)
              if f.severity.value in ("critical", "high")
              and f.confidence.value in ("confirmed", "likely")]
    return 1 if severe else 0


def _print_analysis(analysis) -> None:
    """Print the AI narrative under the CLI report."""
    print()
    print("─" * 70)
    print("  AI analysis", f"(model: {analysis.model})")
    print("─" * 70)
    if analysis.plain_english:
        print("\n  Plain-English summary")
        for line in analysis.plain_english.splitlines():
            print(f"    {line}")
    if analysis.key_risks:
        print("\n  Key risks")
        for risk in analysis.key_risks:
            print(f"    • {risk}")
    if analysis.in_depth:
        print("\n  In-depth analysis")
        for line in analysis.in_depth.splitlines():
            print(f"    {line}")
    if analysis.recommendations:
        print("\n  Recommendations")
        for rec in analysis.recommendations:
            print(f"    → {rec}")
    print()


def _cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required for the web UI: pip install -e .", file=sys.stderr)
        return 4
    from .web.app import create_app  # noqa: F401  (import check)

    host = args.host or os.environ.get("DESKSCANNER_WEB_HOST", "127.0.0.1")
    port = args.port or int(os.environ.get("DESKSCANNER_WEB_PORT", "8765"))
    print(f"deskscanner web UI on http://{host}:{port}  (Ctrl-C to stop)")
    uvicorn.run("deskscanner.web.app:app", host=host, port=port, log_level="warning")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deskscanner",
        description="Static security scanner for Electron desktop apps + safe "
                    "loopback inspection.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="Scan an installed Electron app.")
    sc.add_argument("target", help="Path to the app dir, .app bundle, or app.asar.")
    sc.add_argument("--probe", action="store_true",
                    help="Enable the safe read-only loopback API probe.")
    sc.add_argument("--probe-timeout", type=float, default=float(
        os.environ.get("DESKSCANNER_PROBE_TIMEOUT", "4.0")),
                    help="Per-request probe timeout (seconds).")
    sc.add_argument("--storage-path", action="append",
                    help="Explicit on-disk data dir to inspect (repeatable).")
    sc.add_argument("--mode", choices=["security", "efficiency", "all"],
                    default="all",
                    help="Analysis axes to run (default 'all' — both security and "
                         "efficiency, each with its own grade). Use 'security' or "
                         "'efficiency' to run just one.")
    sc.add_argument("--json", metavar="FILE", help="Write a JSON report.")
    sc.add_argument("--html", metavar="FILE", help="Write a standalone HTML report.")
    sc.add_argument("--pdf", metavar="FILE", help="Write a polished, branded PDF report.")
    sc.add_argument("--analyze", action="store_true",
                    help="Add an AI in-depth analysis + plain-English explanation "
                         "of the findings (requires ANTHROPIC_API_KEY).")
    sc.add_argument("--diff", metavar="PREV.json",
                    help="Diff against a previous JSON report (ignores volatile).")
    sc.add_argument("--format", choices=["cli", "json"], default="cli",
                    help="Stdout format (default cli).")
    sc.add_argument("--yes", action="store_true",
                    help="Skip the interactive authorization prompt.")
    sc.add_argument("--quiet", action="store_true", help="Suppress progress lines.")
    sc.set_defaults(func=_cmd_scan, mode="all")

    ef = sub.add_parser("efficiency",
                        help="Analyze an Electron app's efficiency / footprint "
                             "(static; no runtime profiling).")
    ef.add_argument("target", help="Path to the app dir, .app bundle, or app.asar.")
    ef.add_argument("--json", metavar="FILE", help="Write a JSON report.")
    ef.add_argument("--html", metavar="FILE", help="Write a standalone HTML report.")
    ef.add_argument("--pdf", metavar="FILE", help="Write a polished, branded PDF report.")
    ef.add_argument("--format", choices=["cli", "json"], default="cli",
                    help="Stdout format (default cli).")
    ef.add_argument("--yes", action="store_true",
                    help="Skip the interactive authorization prompt.")
    ef.add_argument("--quiet", action="store_true", help="Suppress progress lines.")
    ef.set_defaults(func=_cmd_scan, mode="efficiency")

    sv = sub.add_parser("serve", help="Launch the local web UI.")
    sv.add_argument("--host", default=None)
    sv.add_argument("--port", type=int, default=None)
    sv.set_defaults(func=_cmd_serve)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # Output was piped into something that closed early (e.g. `| head`).
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
