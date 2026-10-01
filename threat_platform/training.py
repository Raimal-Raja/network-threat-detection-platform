"""Train/evaluate a simulated completed-flow detector; no production promotion."""
import argparse
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_curve, auc
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .features import (FEATURE_NAMES, FEATURE_VERSION, encode, split_rows,
                       audit_parts, threshold_at_fpr)
from .ingestion import sha256_file, verify_run


def score_report(labels, scores, threshold):
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=np.float64)  # Preserve nextafter cutoff.
    if scores.shape != labels.shape or set(labels.tolist()) != {0, 1}:
        raise ValueError("scores and both classes required")
    if not np.isfinite(scores).all():
        raise ValueError("scores must be finite")
    alerts = scores >= threshold
    precision, recall, _ = precision_recall_curve(labels, scores)
    return {
        "average_precision": float(average_precision_score(labels, scores)),
        "pr_auc_trapezoidal": float(auc(recall[::-1], precision[::-1])),
        "recall": float(alerts[labels == 1].mean()),
        "false_positive_rate": float(alerts[labels == 0].mean()),
        "false_alert_count": int(alerts[labels == 0].sum()),
        "benign_count": int((labels == 0).sum()),
        "suspicious_count": int((labels == 1).sum()),
        "threshold": threshold}


def predict_bundle(bundle, rows):
    bundle = Path(bundle)
    metadata = json.loads((bundle / "metadata.json").read_text())
    if (metadata["feature_version"] != FEATURE_VERSION
            or metadata["feature_names"] != FEATURE_NAMES):
        raise ValueError("unsupported feature contract")
    if sha256_file(bundle / "model.json") != metadata["model_sha256"]:
        raise ValueError("model checksum mismatch")
    model = xgb.XGBClassifier()
    model.load_model(bundle / "model.json")
    model.set_params(device="cpu")
    scores = model.predict_proba(encode(rows))[:, 1].astype(np.float64)
    threshold = metadata["threshold"]
    return [{"suspicious_score": float(s), "alert": bool(s >= threshold)}
            for s in scores]


def train_run(run_dir, output, device="cpu", target_fpr=.01):
    run_dir, output = Path(run_dir), Path(output)
    if output.exists():
        raise ValueError("output exists; choose a new run name")
    provenance = verify_run(run_dir)
    rows = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
    parts = split_rows(rows)
    audit = audit_parts(parts)
    X = {k: encode(v) for k, v in parts.items()}
    y = {k: np.asarray([r["label"] for r in v]) for k, v in parts.items()}
    requested_device = device
    if device == "auto":
        device = ("cuda" if shutil.which("nvidia-smi") and subprocess.run(
            ["nvidia-smi"], capture_output=True).returncode == 0 else "cpu")
    if device not in ("cpu", "cuda"):
        raise ValueError("device must be cpu, cuda, or auto")
    models = {
        "dummy": DummyClassifier(strategy="prior"),
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(
            max_iter=2000, random_state=42)),
        "xgboost": xgb.XGBClassifier(
            n_estimators=150, max_depth=4, learning_rate=.05,
            tree_method="hist", device=device, objective="binary:logistic",
            eval_metric="aucpr", random_state=42, n_jobs=2)}
    results = {}
    for name, model in models.items():
        start = time.perf_counter()
        model.fit(X["train"], y["train"])
        elapsed = time.perf_counter() - start
        if name == "xgboost":
            actual = json.loads(model.get_booster().save_config())["learner"]["generic_param"]["device"]
            if device == "cuda" and not actual.startswith("cuda"):
                raise RuntimeError("GPU requested but XGBoost fell back to CPU")
            model.set_params(device="cpu")
        scores = model.predict_proba(X["validation"])[:, 1].astype(np.float64)
        threshold = threshold_at_fpr(y["validation"], scores, target_fpr)
        results[name] = {"fit_seconds": elapsed, "threshold": threshold,
                         "validation": score_report(y["validation"], scores, threshold)}
    # Choose only from validation AP. This is an analysis recommendation, not deployment.
    selected = max(results, key=lambda name: results[name]["validation"]["average_precision"])
    for name, model in models.items():
        scores = model.predict_proba(X["test"])[:, 1].astype(np.float64)
        results[name]["test"] = score_report(y["test"], scores, results[name]["threshold"])
    model = models["xgboost"]
    threshold = results["xgboost"]["threshold"]
    baseline = models["logistic_regression"]
    report = {
        "simulated": True, "production_ready": False,
        "evaluation_status": "development_holdout_already_inspected",
        "requested_device": requested_device, "actual_training_device": actual,
        "target_validation_fpr": target_fpr,
        "validation_benign_count": int((y["validation"] == 0).sum()),
        "minimum_nonzero_validation_fpr": 1 / int((y["validation"] == 0).sum()),
        "validation_selected_model": selected, "exported_model": "xgboost",
        "promotion_decision": "not_promoted_research_demo",
        "xgboost_test_fpr_within_target": results["xgboost"]["test"]["false_positive_rate"] <= target_fpr,
        "false_alerts_per_day": None,
        "false_alerts_per_day_reason": "Less than one complete observed day; no daily extrapolation.",
        "service_throughput": None, "service_p95_latency_ms": None,
        "models": results, "audit": audit}
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".train-", dir=output.parent))
    try:
        model.save_model(stage / "model.json")
        source_file = Path(__file__).with_name("features.py")
        shutil.copyfile(source_file, stage / "features.py")
        shutil.copyfile(run_dir / "manifest.json", stage / "data-manifest.json")
        def save(name, value):
            (stage / name).write_text(json.dumps(value, indent=2, sort_keys=True,
                                                allow_nan=False) + "\n", encoding="utf-8")
        save("baseline-logistic.json", {
            "feature_names": FEATURE_NAMES,
            "scaler_mean": baseline[0].mean_.tolist(),
            "scaler_scale": baseline[0].scale_.tolist(),
            "coefficients": baseline[1].coef_.tolist(),
            "intercept": baseline[1].intercept_.tolist(),
            "classes": baseline[1].classes_.tolist(),
            "threshold": results["logistic_regression"]["threshold"]})
        save("metadata.json", {
            "artifact_version": 1, "feature_version": FEATURE_VERSION,
            "feature_names": FEATURE_NAMES, "threshold": threshold,
            "simulated": True, "production_ready": False,
            "actual_training_device": actual, "seed": 42,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "model_sha256": sha256_file(stage / "model.json"),
            "events_sha256": provenance["events_sha256"],
            "packages": {p: importlib.metadata.version(p)
                         for p in ("numpy", "scipy", "scikit-learn", "xgboost")},
            "python": platform.python_version(),
            "code_sha256": {p.name: sha256_file(p) for p in sorted(Path(__file__).parent.glob("*.py"))},
            "model_parameters": model.get_params()})
        # Reload the actual saved JSON and test every held-out row on CPU.
        restored = predict_bundle(stage, parts["test"])
        original = model.predict_proba(X["test"])[:, 1].astype(np.float64)
        np.testing.assert_allclose([r["suspicious_score"] for r in restored],
                                   original, rtol=0, atol=1e-7)
        if [r["alert"] for r in restored] != (original >= threshold).tolist():
            raise RuntimeError("saved model alert decisions changed")
        report["save_reload_check"] = "passed_all_test_rows_on_cpu"
        save("metrics.json", report)
        save("split-audit.json", audit)
        (stage / "README.md").write_text(
            "# SIMULATED threat model bundle\n\n"
            "This is a research candidate, not a production-approved detector.\n"
            "Read metrics.json, split-audit.json and data-manifest.json before interpreting scores.\n"
            "Features: completed-flow duration_us, packets, bytes, and protocol; see features.py.\n"
            "The XGBoost model uses JSON. predict_bundle verifies its hash and runs on CPU.\n"
            "The validation threshold is not a guarantee of test or future false-positive rate.\n"
            "The test period was inspected during development; acquire independent captures before claims.\n",
            encoding="utf-8")
        if output.exists():
            raise ValueError("output appeared during training; refusing overwrite")
        os.rename(stage, output)
    finally:
        if stage.exists():
            for path in stage.iterdir():
                path.unlink()
            stage.rmdir()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--device", choices=["cpu", "cuda", "auto"], default="cpu")
    parser.add_argument("--target-fpr", type=float, default=.01)
    args = parser.parse_args()
    try:
        report = train_run(args.data, args.output, args.device, args.target_fpr)
    except (ValueError, OSError, RuntimeError, KeyError, TypeError) as exc:
        parser.exit(2, f"Training failed: {exc}\n")
    print(json.dumps({k: v for k, v in report.items() if k != "audit"}, indent=2))


if __name__ == "__main__":
    main()
