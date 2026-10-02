"""Sequential loopback HTTP benchmark; simulated input, not detection evaluation."""
import argparse
import json
import math
import platform
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def benchmark(url, requests=200, warmup=20, batch_size=1):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("benchmark requires a local HTTP service")
    if requests < 1 or warmup < 0 or not 1 <= batch_size <= 256:
        raise ValueError("invalid benchmark configuration")
    flow = dict(duration_us=1000, packets=12, bytes=4096, protocol="TCP")
    path = "/predict" if batch_size == 1 else "/predict/batch"
    payload = flow if batch_size == 1 else {"events": [flow] * batch_size}
    body = json.dumps(payload).encode()
    def call():
        request = urllib.request.Request(url.rstrip("/") + path, data=body,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
        predictions = [result] if batch_size == 1 else result["predictions"]
        if len(predictions) != batch_size:
            raise ValueError("wrong response count")
        identities = {(p["model_version"], p["bundle_sha256"]) for p in predictions}
        if len(identities) != 1:
            raise ValueError("mixed model versions")
        return identities.pop()
    identity = call()  # Establish readiness; exclude from warmup/timed results.
    for _ in range(warmup):
        if call() != identity:
            raise ValueError("model changed during warmup")
    latencies, errors, successes = [], 0, 0
    start = time.perf_counter()
    for _ in range(requests):
        before = time.perf_counter()
        try:
            if call() != identity:
                raise ValueError("model changed during benchmark")
            latencies.append((time.perf_counter() - before) * 1000)
            successes += 1
        except (OSError, ValueError, KeyError):
            errors += 1
    elapsed = time.perf_counter() - start
    ordered = sorted(latencies)
    return {"simulated": True, "production_ready": False,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "url": url, "endpoint": path, "model_version": identity[0],
            "bundle_sha256": identity[1], "requests": requests, "warmup": warmup,
            "batch_size": batch_size, "concurrency": 1, "successful_requests": successes,
            "errors": errors, "error_rate": errors / requests, "duration_seconds": elapsed,
            "successful_requests_per_second": successes / elapsed,
            "events_per_second": successes * batch_size / elapsed,
            "p95_successful_request_latency_ms": ordered[math.ceil(.95 * len(ordered)) - 1] if ordered else None,
            "client_python": platform.python_version(), "client_platform": platform.platform(),
            "limitations": "Sequential loopback synthetic traffic; report server hardware/workers separately. Latency excludes failures; throughput includes their elapsed time."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("output exists; choose another filename")
        report = benchmark(args.url, args.requests, args.warmup, args.batch_size)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as output:
            output.write(json.dumps(report, indent=2, allow_nan=False) + "\n")
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(2, f"Benchmark failed: {exc}\n")
    print(json.dumps(report, indent=2))
    if report["errors"]:
        parser.exit(1, "Benchmark completed with request failures\n")


if __name__ == "__main__":
    main()
