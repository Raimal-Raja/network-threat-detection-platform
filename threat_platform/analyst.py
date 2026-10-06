"""Analyst routes; review history stays available when inference is unavailable."""
import logging
import sqlite3
from pathlib import Path
from typing import Literal
from fastapi import HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .cases import Conflict, MissingCase
from .schemas import CaseInput, FeedbackInput

logger = logging.getLogger(__name__)


def add_routes(app, assess):
    def store():
        value = getattr(app.state, "cases", None)
        if value is None:
            raise HTTPException(status_code=503, detail="case storage unavailable")
        return value

    def write_origin(request):
        origin = request.headers.get("origin")
        if origin is not None and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(status_code=403, detail="cross-origin writes are not supported")

    def run(action):
        try:
            return action()
        except Conflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except MissingCase:
            raise HTTPException(status_code=404, detail="case not found")
        except (OSError, sqlite3.Error):
            logger.exception("Analyst storage failed")
            raise HTTPException(status_code=503, detail="case storage unavailable")

    static = Path(__file__).with_name("static")
    app.mount("/assets", StaticFiles(directory=static), name="analyst-assets")

    @app.get("/analyst", include_in_schema=False)
    def dashboard():
        return FileResponse(static / "analyst.html", headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            "X-Content-Type-Options": "nosniff"})

    @app.get("/analyst/status")
    def status():
        return {"case_storage_ready": getattr(app.state, "cases", None) is not None,
                "model_ready": getattr(app.state, "predictor", None) is not None,
                "simulated": True, "production_ready": False}

    @app.post("/cases")
    def create_case(payload: CaseInput, request: Request):
        write_origin(request)
        database = store()
        flow = payload.flow.model_dump()
        prediction, explanation = assess(flow)
        return run(lambda: database.save(payload.event_id, flow, prediction, explanation))

    @app.get("/cases")
    def list_cases(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0, le=100000),
                   alert_only: bool = False,
                   review: Literal["all", "unreviewed", "suspicious", "benign", "uncertain"] = "all"):
        return run(lambda: store().list(limit, offset, alert_only, review))

    @app.get("/cases/{case_id}")
    def case_detail(case_id: str):
        return run(lambda: store().get(case_id))

    @app.post("/cases/{case_id}/feedback")
    def feedback(case_id: str, payload: FeedbackInput, request: Request):
        write_origin(request)
        return run(lambda: store().feedback(case_id, payload.expected_revision,
                                           payload.reviewer, payload.verdict, payload.note))
