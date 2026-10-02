"""Offline experiment ledger and immutable, checksum-verified research versions."""
import argparse
import hashlib
import json
import math
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = {"model.json", "metadata.json", "metrics.json", "split-audit.json",
            "baseline-logistic.json", "features.py", "data-manifest.json", "README.md"}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    def reject(value):
        raise ValueError("nonfinite JSON value: " + value)
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=reject)


def inspect_bundle(bundle):
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle must be a real directory")
    files = list(bundle.iterdir())
    if {p.name for p in files} != REQUIRED:
        raise ValueError("bundle must contain exactly the eight Step 4 files")
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError("bundle files must be regular files, not links")
    metadata = read_json(bundle / "metadata.json")
    metrics = read_json(bundle / "metrics.json")
    if metadata.get("artifact_version") != 1:
        raise ValueError("unsupported artifact version")
    if metadata.get("simulated") is not True or metrics.get("simulated") is not True:
        raise ValueError("only simulated research bundles are supported")
    if metadata.get("production_ready") is not False or metrics.get("production_ready") is not False:
        raise ValueError("Step 5 cannot approve production models")
    if metrics.get("save_reload_check") != "passed_all_test_rows_on_cpu":
        raise ValueError("missing Step 4 save/reload evidence")
    if digest(bundle / "model.json") != metadata.get("model_sha256"):
        raise ValueError("model checksum mismatch")
    for field in ("feature_version", "feature_names", "packages", "code_sha256",
                  "events_sha256", "model_parameters", "threshold"):
        if field not in metadata:
            raise ValueError("missing metadata: " + field)
    if not isinstance(metadata["threshold"], (int, float)) or not math.isfinite(metadata["threshold"]):
        raise ValueError("invalid threshold")
    if not isinstance(metrics.get("models"), dict) or "xgboost" not in metrics["models"]:
        raise ValueError("missing model comparison")
    # Parse every structured artifact before accepting it.
    for p in files:
        if p.suffix == ".json":
            read_json(p)
    hashes = {p.name: digest(p) for p in sorted(files)}
    fingerprint = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    return {"bundle_sha256": fingerprint, "files": hashes,
            "metadata": metadata, "metrics": metrics}


def connect(store):
    store = Path(store)
    store.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(store / "experiments.sqlite3", timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE IF NOT EXISTS versions (
        version INTEGER PRIMARY KEY AUTOINCREMENT,
        bundle_sha256 TEXT UNIQUE NOT NULL,
        created_at_utc TEXT NOT NULL,
        note TEXT NOT NULL,
        report_json TEXT NOT NULL)""")
    connection.commit()
    return connection


def verify_record(store, row):
    report = json.loads(row["report_json"])
    current = inspect_bundle(Path(store) / "bundles" / row["bundle_sha256"])
    if current != report:
        raise ValueError("registered bundle changed; refusing to use it")
    return {"version": row["version"], "bundle_sha256": row["bundle_sha256"],
            "created_at_utc": row["created_at_utc"], "note": row["note"],
            "status": "research_candidate", "production_ready": False,
            "report": report}


def register(bundle, store, note=""):
    store = Path(store)
    report = inspect_bundle(bundle)
    fingerprint = report["bundle_sha256"]
    bundle_root = store / "bundles"
    bundle_root.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".register-", dir=bundle_root))
    connection = None
    try:
        for name in REQUIRED:
            shutil.copyfile(Path(bundle) / name, stage / name)
        # Detect a source changed during copying.
        if inspect_bundle(stage) != report:
            raise ValueError("bundle changed while registering")
        connection = connect(store)
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            "SELECT * FROM versions WHERE bundle_sha256=?", (fingerprint,)).fetchone()
        if existing:
            result = verify_record(store, existing)
            connection.commit()
            return result
        target = bundle_root / fingerprint
        if target.exists():
            # Recover a verified directory left by a crash before DB commit.
            if inspect_bundle(target) != report:
                raise ValueError("existing snapshot checksum mismatch")
        else:
            os.rename(stage, target)
        connection.execute(
            "INSERT INTO versions(bundle_sha256, created_at_utc, note, report_json) VALUES(?,?,?,?)",
            (fingerprint, datetime.now(timezone.utc).isoformat(), note,
             json.dumps(report, sort_keys=True, allow_nan=False)))
        row = connection.execute(
            "SELECT * FROM versions WHERE bundle_sha256=?", (fingerprint,)).fetchone()
        result = verify_record(store, row)
        connection.commit()
        return result
    finally:
        if connection is not None:
            connection.close()  # Uncommitted DB work rolls back on failure.
        if stage.exists():
            shutil.rmtree(stage)


def versions(store):
    connection = connect(store)
    try:
        return [verify_record(store, row) for row in
                connection.execute("SELECT * FROM versions ORDER BY version")]
    finally:
        connection.close()


def show(store, version):
    connection = connect(store)
    try:
        row = connection.execute("SELECT * FROM versions WHERE version=?", (version,)).fetchone()
        if row is None:
            raise ValueError("unknown version")
        return verify_record(store, row)
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, default=Path("artifacts/tracking"))
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("register")
    add.add_argument("--bundle", type=Path, required=True)
    add.add_argument("--note", default="")
    commands.add_parser("list")
    detail = commands.add_parser("show")
    detail.add_argument("version", type=int)
    args = parser.parse_args()
    try:
        if args.command == "register":
            result = register(args.bundle, args.store, args.note)
        elif args.command == "list":
            result = versions(args.store)
        else:
            result = show(args.store, args.version)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as exc:
        parser.exit(2, f"Tracking failed: {exc}\n")
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
