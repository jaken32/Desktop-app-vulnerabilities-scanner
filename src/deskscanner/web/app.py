"""FastAPI backend for the local web UI.

Bound to localhost by the CLI. Exposes:
  GET  /            the single-page UI
  POST /api/scan    run a scan (JSON in/out); requires explicit consent
  POST /api/diff    diff an uploaded previous report against a fresh scan
  GET  /healthz     liveness

All scan output is returned as structured JSON; the SPA renders it using
textContent so hostile bundle strings can never inject markup.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..diff import diff_reports
from ..engine import scan
from ..locate import TargetNotElectronError
from ..reporting.html import render_html
from ..unpack import UnpackError, UnpackLimits

_HERE = os.path.dirname(__file__)
_STATIC = os.path.join(_HERE, "static")
_TEMPLATES = os.path.join(_HERE, "templates")


class ScanRequest(BaseModel):
    target: str
    mode: str = "security"
    probe: bool = False
    consent: bool = False
    previous_report: dict | None = None


def create_app() -> FastAPI:
    app = FastAPI(title="deskscanner", docs_url=None, redoc_url=None)

    if os.path.isdir(_STATIC):
        app.mount("/static", StaticFiles(directory=_STATIC), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        with open(os.path.join(_TEMPLATES, "index.html"), encoding="utf-8") as fp:
            return HTMLResponse(fp.read())

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.post("/api/scan")
    def api_scan(req: ScanRequest) -> JSONResponse:
        if not req.consent:
            return JSONResponse(
                {"error": "Authorization not confirmed. Tick the consent box to "
                          "confirm you are allowed to scan this target."},
                status_code=400,
            )
        if not req.target.strip():
            return JSONResponse({"error": "Please provide a target path."},
                                status_code=400)
        mode = req.mode if req.mode in ("security", "efficiency", "all") else "security"
        try:
            result = scan(
                req.target.strip(),
                mode=mode,
                probe=req.probe,
                limits=UnpackLimits.from_env(),
            )
        except TargetNotElectronError as exc:
            return JSONResponse({"error": f"Not an Electron target: {exc}"},
                                status_code=422)
        except UnpackError as exc:
            return JSONResponse({"error": f"Could not safely read the bundle: {exc}"},
                                status_code=422)
        except Exception as exc:  # pragma: no cover - last-resort guard
            return JSONResponse(
                {"error": "An unexpected error occurred while scanning. "
                          f"({type(exc).__name__})"},
                status_code=500,
            )

        diff = None
        if req.previous_report:
            try:
                diff = diff_reports(req.previous_report, result).to_dict()
            except ValueError:
                diff = None

        payload = result.to_dict()
        payload["diff"] = diff
        payload["html"] = render_html(
            result,
            diff=diff_reports(req.previous_report, result) if req.previous_report else None,
        )
        return JSONResponse(payload)

    return app


app = create_app()
