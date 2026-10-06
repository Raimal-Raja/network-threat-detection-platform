"""SIMULATED replay of verified public events through a loopback prediction service."""
import argparse
import hashlib
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.stats import ks_2samp
from .features import encode, split_rows, completion_time, NUMERIC_FIELDS
from .ingestion import verify_run
from .schemas import Flow
from .training import score_report

def local_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1") or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("a loopback HTTP service URL is required")
    return url.rstrip("/")

def http(url, path, payload=None):
    body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
    request = urllib.request.Request(local_url(url) + path, data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)

def flow(row):
    return {key: row[key] for key in (*NUMERIC_FIELDS, "protocol")}

def drift(reference, current):
    if not reference or not current:
        raise ValueError("nonempty drift samples required")
    a, b = encode(reference), encode(current)
    numeric = {}
    for i, name in enumerate(NUMERIC_FIELDS):
        result = ks_2samp(a[:, i], b[:, i])
        numeric[name] = {"ks_distance": float(result.statistic), "p_value": float(result.pvalue)}
    pa, pb = Counter(r["protocol"] for r in reference), Counter(r["protocol"] for r in current)
    tv = sum(abs(pa[p]/len(reference) - pb[p]/len(current)) for p in ("TCP", "UDP", "ICMP")) / 2
    return {"reference_rows": len(reference), "current_rows": len(current), "numeric": numeric,
            "protocol_total_variation": tv,
            "investigate": any(v["ks_distance"] >= .2 for v in numeric.values()) or tv >= .2,
            "policy": "KS distance or protocol TV >= 0.2 is an illustrative heuristic, not a calibrated significance test."}

def evaluate(rows, predictions, threshold):
    if len(rows) != len(predictions) or not rows:
        raise ValueError("one prediction per nonempty row required")
    labels = [r["label"] for r in rows]
    if any(type(y) is not int or y not in (0, 1) for y in labels):
        raise ValueError("binary labels required")
    scores = [p["suspicious_score"] for p in predictions]
    if any(type(s) not in (int, float) or not math.isfinite(s) or not 0 <= s <= 1 for s in scores):
        raise ValueError("invalid scores")
    if any(type(p["alert"]) is not bool or p["alert"] != (p["suspicious_score"] >= threshold) for p in predictions):
        raise ValueError("inconsistent alert decisions")
    counts = {}
    for row, prediction in zip(rows, predictions):
        day = completion_time(row).date().isoformat()
        daily = counts.setdefault(day, {"events": 0, "benign": 0, "false_alerts": 0})
        daily["events"] += 1
        daily["benign"] += int(row["label"] == 0)
        daily["false_alerts"] += int(row["label"] == 0 and prediction["alert"])
    metrics = score_report(labels, scores, threshold) if set(labels) == {0, 1} else None
    return {"metrics": metrics, "daily_observed_counts": counts,
            "false_alerts_per_day": None,
            "false_alerts_per_day_reason": "Selected events do not establish complete continuous-day coverage; no extrapolation.",
            "first_completion_utc": min(completion_time(r) for r in rows).isoformat(),
            "last_completion_utc": max(completion_time(r) for r in rows).isoformat()}

def replay(run_dir, url, limit=1000, batch_size=32, shift=1, invalid_probe=False):
    if type(limit) is not int or limit < 1 or not 1 <= batch_size <= 256 or type(shift) is not int or not 1 <= shift <= 100:
        raise ValueError("invalid replay settings")
    run_dir = Path(run_dir)
    provenance = verify_run(run_dir)
    rows = [json.loads(line) for line in (run_dir/"events.jsonl").read_text().splitlines()]
    parts = split_rows(rows)
    original = parts["test"][:limit]
    current = [{**r, "bytes": min(2**63-1, r["bytes"] * shift),
                "packets": min(2**63-1, r["packets"] * shift)} for r in original]
    for row in current:
        Flow.model_validate(flow(row))
    info = http(url, "/model")
    identity = (info["model_version"], info["bundle_sha256"])
    results, latency, errors = [], [], []
    start = time.perf_counter()
    for offset in range(0, len(current), batch_size):
        batch = current[offset:offset+batch_size]
        before = time.perf_counter()
        try:
            output = http(url, "/predict/batch", {"events": [flow(r) for r in batch]})
            preds = output["predictions"]
            if len(preds) != len(batch) or output["count"] != len(batch):
                raise ValueError("response count mismatch")
            if any((p["model_version"], p["bundle_sha256"]) != identity or p["threshold"] != info["threshold"] for p in preds):
                raise ValueError("model identity or threshold changed during replay")
            # Validate complete response before accepting the batch.
            evaluate(batch, preds, info["threshold"])
            results.extend(zip(batch, preds))
            latency.append((time.perf_counter()-before)*1000)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append({"offset": offset, "rows": len(batch), "kind": type(exc).__name__})
    elapsed = time.perf_counter() - start
    probe = None
    if invalid_probe:
        try:
            http(url, "/predict", {"duration_us": 1000, "packets": -1, "bytes": 20, "protocol": "TCP"})
            probe = {"expected_status": 422, "passed": False}
        except urllib.error.HTTPError as exc:
            probe = {"expected_status": 422, "actual_status": exc.code, "passed": exc.code == 422}
        except OSError:
            probe = {"expected_status": 422, "passed": False, "reason": "transport_failure"}
    accepted, predictions = ([r for r, p in results], [p for r, p in results])
    detection = evaluate(accepted, predictions, info["threshold"]) if accepted and shift == 1 and not errors else None
    order = sorted(latency)
    return {"report_version": 1, "simulated": True, "production_ready": False,
            "evaluation_scope": "development_within_capture", "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "model_version": identity[0], "bundle_sha256": identity[1], "threshold": info["threshold"],
            "events_sha256": provenance["events_sha256"],
            "replay_order_sha256": hashlib.sha256(("\n".join(r["event_id"] for r in current)+"\n").encode()).hexdigest(),
            "attempted_events": len(current), "successful_events": len(results), "errors": errors,
            "shift_multiplier": shift, "detection": detection,
            "drift": drift(parts["train"], current), "invalid_input_probe": probe,
            "duration_seconds": elapsed, "events_per_second": len(results)/elapsed,
            "p95_successful_batch_latency_ms": order[math.ceil(.95*len(order))-1] if order else None,
            "batch_size": batch_size, "concurrency": 1,
            "limitations": "Accelerated selected test-slice replay; no real-time pacing, complete-day coverage or independent evaluation. Shifted labels are not assumed valid; detection metrics suppressed after perturbation or any failure."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--shift", type=int, default=1)
    parser.add_argument("--invalid-probe", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("output exists; choose a new report name")
        report = replay(args.data, args.url, args.limit, args.batch_size, args.shift, args.invalid_probe)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as target:
            target.write(json.dumps(report, indent=2, allow_nan=False)+"\n")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"Replay failed: {exc}\n")
    print(json.dumps(report, indent=2))
    if report["errors"] or (report["invalid_input_probe"] and not report["invalid_input_probe"]["passed"]):
        parser.exit(1, "Replay completed with failed checks\n")

if __name__ == "__main__":
    main()
