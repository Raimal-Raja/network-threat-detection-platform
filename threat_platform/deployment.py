"""Local simulation activation with verified versions, revision checks and rollback."""
import argparse
import json
import math
import sqlite3
import os
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .tracking import show, read_json, REQUIRED, connect

@contextmanager
def database(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS state (
            id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL,
            version INTEGER NOT NULL, bundle_sha256 TEXT NOT NULL, store TEXT NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS history (
            revision INTEGER PRIMARY KEY, action TEXT NOT NULL, version INTEGER NOT NULL,
            bundle_sha256 TEXT NOT NULL, store TEXT NOT NULL, created_at_utc TEXT NOT NULL)""")
        db.commit()
        with db:
            yield db
    finally:
        db.close()

def state(path):
    with database(path) as db:
        row = db.execute("SELECT * FROM state WHERE id=1").fetchone()
        return dict(row) if row else None

def selected_version(path, store):
    current = state(path)
    if current is None:
        raise ValueError("no active simulation version")
    if current["store"] != str(Path(store).resolve()):
        raise ValueError("deployment store mismatch")
    record = show(store, current["version"])
    if record["bundle_sha256"] != current["bundle_sha256"]:
        raise ValueError("active bundle mismatch")
    return current["version"]

def smoke(store, version):
    from .api import Predictor
    predictor = Predictor(store, version)
    row = {"duration_us": 1000, "packets": 12, "bytes": 4096, "protocol": "TCP"}
    prediction = predictor.predict([row])[0]
    explanation = predictor.explain(row)
    if not math.isclose(prediction["suspicious_score"], explanation["reconstructed_score"], abs_tol=1e-6):
        raise ValueError("model explanation smoke check failed")
    return predictor.record

def activate(path, store, version, expected_revision, simulation=False, action="activate"):
    if simulation is not True:
        raise ValueError("only explicit --simulation activation is supported")
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("nonnegative expected revision required")
    if type(version) is not int or version < 1:
        raise ValueError("positive version required")
    if action not in ("activate", "rollback"):
        raise ValueError("unsupported action")
    record = smoke(store, version)  # Checks integrity, compatibility and CPU before state mutation.
    canonical_store = str(Path(store).resolve())
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        old = db.execute("SELECT * FROM state WHERE id=1").fetchone()
        revision = old["revision"] if old else 0
        if revision != expected_revision:
            raise ValueError("deployment revision conflict")
        if old and old["store"] != canonical_store:
            raise ValueError("deployment store mismatch")
        if old and old["version"] == version:
            raise ValueError("version already active")
        if action == "rollback":
            previous = db.execute("SELECT version FROM history WHERE revision=?", (revision-1,)).fetchone()
            if previous is None or previous["version"] != version:
                raise ValueError("rollback target changed")
        revision += 1
        db.execute("INSERT OR REPLACE INTO state VALUES(1,?,?,?,?)",
                   (revision, version, record["bundle_sha256"], canonical_store))
        db.execute("INSERT INTO history VALUES(?,?,?,?,?,?)",
                   (revision, action, version, record["bundle_sha256"], canonical_store,
                    datetime.now(timezone.utc).isoformat()))
    return state(path)

def rollback(path, store, expected_revision, simulation=False):
    current = state(path)
    if current is None or current["revision"] != expected_revision:
        raise ValueError("deployment revision conflict")
    with database(path) as db:
        previous = db.execute("SELECT version FROM history WHERE revision=?", (expected_revision-1,)).fetchone()
    if previous is None:
        raise ValueError("no previous version")
    return activate(path, store, previous["version"], expected_revision, simulation, "rollback")

def gate(store, version, benchmark, max_fpr=.01, min_recall=.9, max_p95_ms=100, min_events_per_second=1):
    bounds = (max_fpr, min_recall, max_p95_ms, min_events_per_second)
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in bounds) or not 0 <= max_fpr < 1 or not 0 <= min_recall <= 1 or max_p95_ms <= 0 or min_events_per_second <= 0:
        raise ValueError("invalid gate policy")
    record = smoke(store, version)
    report = record["report"]["metrics"]
    test = report["models"]["xgboost"]["test"]
    def finite(key):
        value = test.get(key)
        return value if type(value) in (float, int) and math.isfinite(value) else None
    fpr, recall = finite("false_positive_rate"), finite("recall")
    latency, throughput = benchmark.get("p95_successful_request_latency_ms"), benchmark.get("events_per_second")
    valid_latency = type(latency) in (int, float) and math.isfinite(latency) and 0 <= latency <= max_p95_ms
    valid_throughput = type(throughput) in (int, float) and math.isfinite(throughput) and throughput >= min_events_per_second
    checks = {
        "metric_threshold_identity": test.get("threshold") == record["report"]["metadata"]["threshold"] and report["models"]["xgboost"].get("threshold") == record["report"]["metadata"]["threshold"],
        "heldout_fpr": fpr is not None and 0 <= fpr <= max_fpr,
        "heldout_recall": recall is not None and min_recall <= recall <= 1,
        "benign_support": type(test.get("benign_count")) is int and test["benign_count"] >= 1000,
        "suspicious_support": type(test.get("suspicious_count")) is int and test["suspicious_count"] >= 100,
        "benchmark_identity": type(benchmark.get("model_version")) is int and benchmark.get("model_version") == version and benchmark.get("bundle_sha256") == record["bundle_sha256"],
        "benchmark_complete": type(benchmark.get("requests")) is int and benchmark["requests"] >= 100 and type(benchmark.get("successful_requests")) is int and benchmark.get("successful_requests") == benchmark["requests"] and type(benchmark.get("errors")) is int and benchmark.get("errors") == 0,
        "latency": valid_latency,
        "throughput": valid_throughput,
        # Current bundle contract records within-capture development evidence only.
        # Do not accept a manually edited evaluation_status as independent provenance.
        "independent_capture_evidence": False,
        "complete_day_exposure_evidence": False}
    return {"simulated": True, "production_ready": False, "model_version": version,
            "bundle_sha256": record["bundle_sha256"], "decision": "reject_production_promotion",
            "checks": checks, "failed_checks": [key for key, passed in checks.items() if not passed],
            "policy": {"max_fpr": max_fpr, "min_recall": min_recall, "max_p95_ms": max_p95_ms,
                       "min_events_per_second": min_events_per_second},
            "limitations": "Current bundle contract cannot certify independent captures or complete-day exposure. Simulation activation is separate and never overrides this rejection."}


def export_store(store, version, output):
    """Create an explicit readable container copy; preserve original version/fingerprint."""
    output = Path(output)
    if output.exists():
        raise ValueError("export output exists")
    record = smoke(store, version)
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".export-", dir=output.parent))
    try:
        target = stage/"bundles"/record["bundle_sha256"]
        target.mkdir(parents=True)
        source = Path(store)/"bundles"/record["bundle_sha256"]
        for name in REQUIRED:
            shutil.copyfile(source/name, target/name)
        db = connect(stage)
        try:
            db.execute("INSERT INTO versions(version,bundle_sha256,created_at_utc,note,report_json) VALUES(?,?,?,?,?)",
                       (version, record["bundle_sha256"], record["created_at_utc"], record["note"],
                        json.dumps(record["report"], sort_keys=True, allow_nan=False)))
            db.commit()
        finally:
            db.close()
        if show(stage, version) != record:
            raise ValueError("export verification failed")
        # This explicitly requested export is readable by the non-root container UID.
        # Do not modify permissions on the private source registry.
        for path in stage.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        stage.chmod(0o755)
        if output.exists():
            raise ValueError("export output appeared")
        os.rename(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return {"version": version, "bundle_sha256": record["bundle_sha256"],
            "output": str(output), "simulated": True, "production_ready": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, default=Path("artifacts/tracking"))
    parser.add_argument("--state", type=Path, default=Path("artifacts/deployment/state.sqlite3"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    export = commands.add_parser("export-model")
    export.add_argument("version", type=int)
    export.add_argument("--output", type=Path, required=True)
    add = commands.add_parser("activate")
    add.add_argument("version", type=int)
    add.add_argument("--expected-revision", type=int, required=True)
    add.add_argument("--simulation", action="store_true")
    undo = commands.add_parser("rollback")
    undo.add_argument("--expected-revision", type=int, required=True)
    undo.add_argument("--simulation", action="store_true")
    check = commands.add_parser("gate")
    check.add_argument("version", type=int)
    check.add_argument("--benchmark", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "status":
            result = state(args.state)
        elif args.command == "export-model":
            result = export_store(args.store, args.version, args.output)
        elif args.command == "activate":
            result = activate(args.state, args.store, args.version, args.expected_revision, args.simulation)
        elif args.command == "rollback":
            result = rollback(args.state, args.store, args.expected_revision, args.simulation)
        else:
            if args.output.exists():
                raise ValueError("output exists")
            result = gate(args.store, args.version, read_json(args.benchmark))
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as target:
                target.write(json.dumps(result, indent=2, allow_nan=False)+"\n")
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error, RuntimeError) as exc:
        parser.exit(2, f"Deployment failed: {exc}\n")
    print(json.dumps(result, indent=2, allow_nan=False))
    if args.command == "gate":
        parser.exit(1, "Production promotion rejected; see saved gate report\n")

if __name__ == "__main__":
    main()
