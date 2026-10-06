"""Local-only SIMULATED research inference; pinned verified registry version."""
import hashlib
import json
import logging
import math
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from .features import FEATURE_NAMES, FEATURE_VERSION, encode
from .tracking import show
from .schemas import Flow, Batch, MAX_BATCH
from .cases import CaseStore
from .analyst import add_routes
from .monitoring import Monitor, Telemetry

MAX_BODY_BYTES = 65536
logger = logging.getLogger(__name__)


class BodyLimit:
    """Bound received prediction bytes before JSON parsing, including chunked bodies."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not (scope["path"] in ("/predict", "/predict/batch") or (scope["method"] == "POST" and scope["path"].startswith("/cases"))):
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            data = message.get("body", b"")
            size += len(data)
            if size > MAX_BODY_BYTES:
                response = JSONResponse({"detail": "request body exceeds 65536 bytes"}, status_code=413)
                return await response(scope, receive, send)
            chunks.append(data)
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)
        async def replay():
            return {"type": "http.request", "body": body, "more_body": False}
        await self.app(scope, replay, send)


class Predictor:
    def __init__(self, store, version):
        if not (Path(store) / "experiments.sqlite3").is_file():
            raise ValueError("registered model store is missing")
        self.record = show(store, version)
        metadata = self.record["report"]["metadata"]
        if metadata["feature_version"] != FEATURE_VERSION or metadata["feature_names"] != FEATURE_NAMES:
            raise ValueError("unsupported feature contract")
        self.threshold = metadata["threshold"]
        if type(self.threshold) not in (int, float) or not math.isfinite(self.threshold):
            raise ValueError("invalid threshold")
        model_path = Path(store) / "bundles" / self.record["bundle_sha256"] / "model.json"
        model_bytes = model_path.read_bytes()
        if hashlib.sha256(model_bytes).hexdigest() != metadata["model_sha256"]:
            raise ValueError("model changed during startup")
        self.model = xgb.XGBClassifier()
        self.model.load_model(bytearray(model_bytes))
        self.model.set_params(device="cpu", n_jobs=2)
        booster = self.model.get_booster()
        config = json.loads(booster.save_config())
        if booster.num_features() != len(FEATURE_NAMES):
            raise ValueError("model feature count mismatch")
        if config["learner"]["objective"]["name"] != "binary:logistic":
            raise ValueError("binary logistic model required")
        self.lock = threading.Lock()
        # Warm up the same prediction path before declaring readiness.
        self.predict([dict(duration_us=0, packets=0, bytes=0, protocol="TCP")])

    def identity(self):
        return {"model_version": self.record["version"],
                "bundle_sha256": self.record["bundle_sha256"],
                "feature_version": FEATURE_VERSION, "serving_device": "cpu",
                "simulated": True, "production_ready": False}

    def predict(self, rows):
        matrix = encode(rows)
        with self.lock:
            probabilities = self.model.predict_proba(matrix)
        if probabilities.shape != (len(rows), 2):
            raise RuntimeError("invalid model output shape")
        scores = probabilities[:, 1].astype(np.float64)
        if not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any():
            raise RuntimeError("invalid model scores")
        return [{**self.identity(), "suspicious_score": float(score),
                 "threshold": float(self.threshold), "alert": bool(score >= self.threshold)}
                for score in scores]


    def explain(self, row):
        matrix = encode([row])
        data = xgb.DMatrix(matrix, nthread=2)
        with self.lock:
            booster = self.model.get_booster()
            values = booster.predict(data, pred_contribs=True, approx_contribs=False)[0].astype(np.float64)
            margin = float(booster.predict(data, output_margin=True)[0])
        if values.shape != (len(FEATURE_NAMES) + 1,) or not np.isfinite(values).all() or not math.isfinite(margin):
            raise RuntimeError("invalid explanation")
        if not math.isclose(float(values.sum()), margin, rel_tol=1e-5, abs_tol=5e-5):
            raise RuntimeError("explanation additivity failed")
        score = 1 / (1 + math.exp(-margin)) if margin >= 0 else math.exp(margin) / (1 + math.exp(margin))
        return {"method": "exact_tree_shap", "space": "log_odds",
                "bias": float(values[-1]), "raw_margin": margin, "reconstructed_score": score,
                "additivity_verified": True,
                "contributions": [{"feature": name, "value": float(matrix[0, i]),
                                   "contribution": float(values[i])} for i, name in enumerate(FEATURE_NAMES)],
                "limitation": "Model associations, not causal evidence or proof of malicious activity."}


def create_app(store=None, version=None, case_db=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.predictor = None
        app.state.cases = None
        try:
            app.state.cases = CaseStore(case_db or os.environ.get("THREAT_CASE_DB", "artifacts/analyst/cases.sqlite3"))
        except Exception:
            logger.exception("Case storage startup failed")
        app.state.failure = "model_not_loaded"
        try:
            selected_store = Path(store or os.environ.get("THREAT_MODEL_STORE", "artifacts/tracking"))
            if version is not None:
                selected_version = version
            elif "THREAT_MODEL_VERSION" in os.environ:
                selected_version = int(os.environ["THREAT_MODEL_VERSION"])
            else:
                from .deployment import selected_version as deployed_version
                selected_version = deployed_version(
                    os.environ.get("THREAT_DEPLOYMENT_DB", "artifacts/deployment/state.sqlite3"),
                    selected_store)
            if type(selected_version) is not int or selected_version < 1:
                raise ValueError("positive model version required")
            app.state.predictor = Predictor(selected_store, selected_version)
            app.state.failure = None
        except Exception:
            # Diagnostics stay in server logs; HTTP errors do not disclose paths.
            logger.exception("Research model startup failed")
            app.state.failure = "model_load_failed"
        yield
        app.state.predictor = None

    app = FastAPI(title="SIMULATED network threat inference", version="0.10.0", lifespan=lifespan)
    app.add_middleware(BodyLimit)
    monitor = Monitor()
    app.add_middleware(Telemetry, monitor=monitor)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        # Do not echo raw inputs; NaN inputs also cannot break JSON error serialization.
        errors = [{key: error[key] for key in ("type", "loc", "msg")} for error in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    def loaded():
        predictor = getattr(app.state, "predictor", None)
        if predictor is None:
            raise HTTPException(status_code=503, detail="research model unavailable")
        return predictor

    def infer(rows):
        predictor = loaded()
        try:
            return predictor.predict(rows)
        except Exception:
            logger.exception("Research prediction failed")
            app.state.predictor = None
            app.state.failure = "prediction_failed"
            raise HTTPException(status_code=503, detail="research prediction failed")

    @app.get("/health")
    def health():
        return {"status": "alive", "simulated": True, "production_ready": False}

    @app.get("/ready")
    def ready():
        predictor = loaded()
        return {"status": "ready", **predictor.identity()}

    @app.get("/monitor")
    def monitor_info():
        return monitor.snapshot()

    @app.get("/model")
    def model_info():
        predictor = loaded()
        metrics = predictor.record["report"]["metrics"]
        return {**predictor.identity(), "threshold": predictor.threshold,
                "evaluation_status": metrics.get("evaluation_status"),
                "promotion_decision": metrics.get("promotion_decision"),
                "test": metrics["models"]["xgboost"].get("test")}

    @app.post("/predict")
    def predict(flow: Flow):
        return infer([flow.model_dump()])[0]

    @app.post("/predict/batch")
    def predict_batch(batch: Batch):
        return {"predictions": infer([flow.model_dump() for flow in batch.events]),
                "count": len(batch.events), "simulated": True, "production_ready": False}

    def assess(flow):
        predictor = loaded()
        try:
            prediction = predictor.predict([flow])[0]
            explanation = predictor.explain(flow)
            if not math.isclose(prediction["suspicious_score"], explanation["reconstructed_score"], abs_tol=1e-6):
                raise RuntimeError("explanation score mismatch")
            return prediction, explanation
        except Exception:
            logger.exception("Case assessment failed")
            app.state.predictor = None
            app.state.failure = "assessment_failed"
            raise HTTPException(status_code=503, detail="research assessment failed")

    add_routes(app, assess)

    return app


app = create_app()
