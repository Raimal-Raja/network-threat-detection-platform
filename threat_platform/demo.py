"""End-to-end SIMULATED report from registered model and verified public data."""
import argparse
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from .benchmark import benchmark
from .deployment import gate
from .replay import replay, http
from .tracking import show

def run_demo(data, store, version, url, output, limit=1000):
    output = Path(output)
    if output.exists():
        raise ValueError("demo output exists")
    record = show(store, version)
    ready = http(url, "/ready")
    if ready["model_version"] != version or ready["bundle_sha256"] != record["bundle_sha256"]:
        raise ValueError("running model does not match registry version")
    baseline = replay(data, url, limit=limit, invalid_probe=True)
    shifted = replay(data, url, limit=limit, shift=10)
    performance = benchmark(url, requests=100, warmup=10, batch_size=1)
    expected = (version, record["bundle_sha256"])
    if any((r["model_version"], r["bundle_sha256"]) != expected for r in (baseline, shifted, performance)):
        raise ValueError("model changed between demo measurements")
    decision = gate(store, version, performance)
    if baseline["errors"] or shifted["errors"] or not baseline["invalid_input_probe"]["passed"] or performance["errors"]:
        raise ValueError("demo runtime checks failed")
    case = http(url, "/cases", {"event_id": "demo-"+uuid.uuid4().hex,
                "flow": {"duration_us": 1000, "packets": 104, "bytes": 8200, "protocol": "TCP"}})
    if (case["prediction"]["model_version"], case["prediction"]["bundle_sha256"]) != expected:
        raise ValueError("model changed before analyst case")
    reviewed = http(url, "/cases/"+case["id"]+"/feedback",
                    {"expected_revision": case["revision"], "reviewer": "simulated-demo",
                     "verdict": "uncertain", "note": "Synthetic check; seek capture evidence before classification."})
    if reviewed["prediction"] != case["prediction"] or reviewed["revision"] != case["revision"]+1:
        raise ValueError("review changed original prediction")
    monitoring = http(url, "/monitor")
    report = {"simulated": True, "production_ready": False, "model_version": version,
              "bundle_sha256": record["bundle_sha256"], "case_id": case["id"],
              "analyst_review": "original_prediction_preserved", "promotion": decision["decision"],
              "independent_evaluation": "not_available_requires_new_untouched_capture",
              "false_alerts_per_day": None}
    payloads = {"replay.json": baseline, "shifted.json": shifted, "benchmark.json": performance,
                "gate.json": decision, "monitor.json": monitoring, "summary.json": report}
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".demo-", dir=output.parent))
    try:
        hashes = {}
        for name, value in payloads.items():
            raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+"\n").encode()
            (stage/name).write_bytes(raw)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        (stage/"checksums.json").write_text(json.dumps(hashes, indent=2)+"\n", encoding="utf-8")
        (stage/"README.md").write_text(
            "# SIMULATED end-to-end report\n\n"
            "See summary, replay, shifted, benchmark, gate and monitor JSON reports.\n"
            "No production approval or independent capture evaluation is claimed.\n"
            "Timings depend on local hardware; rerun on your environment.\n"
            "The synthetic case/review persist in the case database.\n", encoding="utf-8")
        if output.exists():
            raise ValueError("output appeared; refusing overwrite")
        os.rename(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--store", type=Path, default=Path("artifacts/tracking"))
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()
    try:
        report = run_demo(args.data, args.store, args.version, args.url, args.output, args.limit)
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as exc:
        parser.exit(2, f"Demo failed: {exc}\n")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
