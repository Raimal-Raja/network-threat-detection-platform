# Step 8 — Simulated replay and monitoring

## Outcome and prerequisites

Replay verified CTU-13 completed flows through the Step 6 batch API, compare current traffic with the training reference, inject an invalid request, and export a measured JSON report. All replay is **SIMULATED**. This milestone adds no paid service.

You need the Step 2 processed dataset and a running Step 7 model service. The model registry alone does not contain events.jsonl; downloading a model does not download the processed data. If absent, obtain it locally using the existing reproducible ingestion commands below.

## Basic concepts

Replay submits recorded events again. Accelerated replay removes the original time spacing, so throughput is an API measurement, not the observed network's event rate. A completed-flow feature exists only after its duration has elapsed. The script orders evaluation by completion time.

Monitoring observes service behavior. Drift measures changes in input distributions. Neither implies that model accuracy changed: verify labels and evaluate independently before deciding to retrain. A traffic perturbation can invalidate a label, which is why shifted scenarios suppress detection metrics.

## Run on D drive

Keep the service running in one PowerShell window. Use a second window:

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
git pull --ff-only origin main
.\.venv\Scripts\python.exe -m pip install -r requirements-service.txt
.\.venv\Scripts\python.exe -m threat_platform download-ctu13
.\.venv\Scripts\python.exe -m threat_platform ingest-ctu13
.\.venv\Scripts\python.exe -m threat_platform verify-ingestion data/processed/ctu13-scenario11-v1
~~~

Skip download/ingestion when that run already verifies. Never replace an existing report accidentally; use new output filenames:

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.replay --data data/processed/ctu13-scenario11-v1 --limit 2175 --batch-size 32 --invalid-probe --output artifacts/replay/baseline-001.json
.\.venv\Scripts\python.exe -m threat_platform.replay --data data/processed/ctu13-scenario11-v1 --limit 2175 --batch-size 32 --shift 10 --output artifacts/replay/shifted-001.json
Invoke-RestMethod http://127.0.0.1:8000/monitor | ConvertTo-Json -Depth 6
~~~

The API client only accepts loopback HTTP addresses. Labels, timestamps and host IDs are excluded from request feature payloads. Replay does not create analyst cases or send data to external services.

## Implementation and reports

replay.py verifies exact source/processed checksums before reading data, recreates the fixed completion-time train/validation/test partition, and uses training rows only as a drift reference. It takes the requested number of test rows and sends batches up to 256 events. The service's model fingerprint and threshold must remain constant across responses.

Reports include events SHA-256, replay event-order hash, model identity, attempted/successful events, failed batch offsets, latency, throughput, drift, invalid-input probe and detection results. No raw measurement payloads are copied into reports.

For unmodified, completely successful replay with both classes, detection contains average precision, trapezoidal PR-AUC, recall and observed FPR at the already-frozen model threshold. The threshold was selected on validation to target 1% FPR; test FPR can exceed it. Do not choose a new cutoff on test scores to claim success.

The invalid probe expects HTTP 422 for a negative packet count. A transport failure or unexpected successful response is a failed probe. Inference failures and model identity changes are counted; the CLI writes their report and exits nonzero. Failed/shifted runs suppress aggregate detection metrics to avoid biased complete-case or invalid-label claims.

## Throughput and latency

Events/second divides successful events by the complete timed batch loop, including failed attempts. p95 uses the nearest-rank 95th percentile of successful batch durations. It includes client serialization and HTTP, excludes readiness and the explicit invalid probe, and is not individual prediction latency. Report batch size, concurrency=1, workers=1 and hardware when comparing results. Step 6 benchmark measures individual-request p95 separately.

Daily counts group false alerts by UTC completion date, but do not establish continuous coverage. false_alerts_per_day remains null: a short selected capture cannot justify daily extrapolation. Unknown/background labels excluded by ingestion are not silently counted as benign.

## Drift from basic to advanced

Numeric log1p features use two-sample Kolmogorov–Smirnov distance. Distance 0 means equal empirical distributions; larger values indicate separation. Protocol proportions use total variation, half the sum of absolute proportion differences. Reports include sample sizes and KS p-values, but the alert heuristic uses effect sizes >=0.2.

The threshold is educational and uncalibrated. Serial dependence, discrete measurements, repeated hosts, changing prevalence and multiple comparisons limit p-value interpretation. Drift can be benign; stable input statistics can still hide concept drift. Small samples and truncated replay can exaggerate differences.

--shift 10 multiplies packet/byte counts and clips to the signed 64-bit input limit. It is a deliberate perturbation, not a new validated traffic dataset. Duration and timestamps remain unchanged, allowing a controlled comparison. Do not reuse its original labels for accuracy claims.

## Service telemetry and failure exercises

monitoring.py records bounded process-local counters and the latest 1,024 successful prediction request latencies. It stores no bodies, event IDs or reviewer notes. /monitor, /health, /ready and static assets do not inflate counters. Validation errors (413/422), server failures and prediction failures remain separate. Successful latency excludes failed requests.

Counters reset on restart and differ per worker. They are not a persistent Prometheus installation, daily alert ledger or distributed observability system. Request duration includes ASGI validation/serialization but excludes client network delay.

Try a baseline replay, a shifted replay and an invalid-input probe. Stop the model service during a replay and inspect errors. Restart and observe counter reset. A monitoring alert recommends investigation; it never retrains, promotes or rolls back automatically.

## Verification and next step

See [verification](verification.md). Unit tests cover identical/shifted traffic, malformed responses, failed batches, URL restrictions, partial-day counts and bounded telemetry. A synthetic live-service CI run exercises the complete report path without claiming public-data operational performance.

Next: [Step 9 deployment checks and rollback](../09-deployment/README.md).
