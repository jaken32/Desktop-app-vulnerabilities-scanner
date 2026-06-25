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

import json
import os
import queue
import threading

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ..diff import diff_reports
from ..engine import scan
from ..locate import TargetNotElectronError
from ..reporting.html import render_html
from ..unpack import UnpackError, UnpackLimits

_VALID_ENGINES = ("electron", "flutter", "native")

_HERE = os.path.dirname(__file__)
_STATIC = os.path.join(_HERE, "static")
_TEMPLATES = os.path.join(_HERE, "templates")


class ScanRequest(BaseModel):
    target: str
    mode: str = "security"
    engine: str | None = None
    probe: bool = False
    prospect: bool = False
    storage_paths: list[str] | None = None
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
        eng = req.engine if req.engine in _VALID_ENGINES else None
        try:
            result = scan(
                req.target.strip(),
                mode=mode,
                engine=eng,
                probe=req.probe,
                prospect=req.prospect,
                storage_paths=req.storage_paths or None,
                limits=UnpackLimits.from_env(),
            )
        except TargetNotElectronError as exc:
            return JSONResponse({"error": f"Not a recognised desktop app bundle: {exc}"},
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

    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    @app.get("/api/scan/stream")
    def api_scan_stream(target: str, mode: str = "all", engine: str | None = None,
                        probe: bool = False, prospect: bool = False,
                        consent: bool = False) -> StreamingResponse:
        """Live progress via Server-Sent Events. Emits `progress` events per
        check, then a single `result` (or `error`) event."""
        def gen():
            if not consent:
                yield _sse("error", {"error": "Authorization not confirmed."})
                return
            if not target.strip():
                yield _sse("error", {"error": "Please provide a target path."})
                return
            m = mode if mode in ("security", "efficiency", "all") else "all"
            eng = engine if engine in _VALID_ENGINES else None
            q: queue.Queue = queue.Queue()

            def progress(name, i, total):
                q.put(("progress", {"phase": name, "i": i, "total": total}))

            def worker():
                try:
                    result = scan(target.strip(), mode=m, engine=eng, probe=probe,
                                  prospect=prospect, limits=UnpackLimits.from_env(),
                                  progress=progress)
                    payload = result.to_dict()
                    payload["html"] = render_html(result)
                    q.put(("result", payload))
                except TargetNotElectronError as exc:
                    q.put(("error", {"error": f"Not a recognised desktop app bundle: {exc}"}))
                except UnpackError as exc:
                    q.put(("error", {"error": f"Could not safely read the bundle: {exc}"}))
                except Exception as exc:  # pragma: no cover - last-resort guard
                    q.put(("error", {"error": f"Unexpected error ({type(exc).__name__})."}))
                finally:
                    q.put(("__done__", {}))

            threading.Thread(target=worker, daemon=True).start()
            while True:
                event, data = q.get()
                if event == "__done__":
                    break
                yield _sse(event, data)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    return app


app = create_app()
