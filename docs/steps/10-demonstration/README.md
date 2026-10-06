# Step 10 — End-to-end demonstration and evaluation handoff

## What is implemented

The project now connects reproducible public-data ingestion, chronological features/training, versioned models, individual/batch inference, explanations, analyst feedback, replay, drift/health monitoring, container checks and explicit simulation rollback. One command assembles an auditable local demonstration report. No paid API or cloud deployment is required.

Independent operational validation is **not complete**. A short reused CTU-13 capture, high selected attack prevalence and overlapping hosts cannot establish real-world detection performance. The project is a runnable research platform, not a production-approved security product.

## Prerequisites from basics

You need Python dependencies, a registered model, the original processed events and a running API. Your downloaded model ZIP contains model artifacts, not events.jsonl. Run reproducible Step 2 ingestion locally if the dataset is absent. Your known registered version is 1, but inspect tracking list before choosing it.

In the first PowerShell:

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
git pull --ff-only origin main
.\.venv\Scripts\python.exe -m pip install -r requirements-service.txt
$env:THREAT_MODEL_STORE = "D:\GitHub\network-threat-detection-platform\artifacts\tracking"
$env:THREAT_MODEL_VERSION = "1"
$env:THREAT_CASE_DB = "D:\GitHub\network-threat-detection-platform\artifacts\analyst\cases.sqlite3"
.\.venv\Scripts\python.exe -m uvicorn threat_platform.api:app --host 127.0.0.1 --port 8000 --workers 1
~~~

In a second PowerShell, prepare data if not already verified:

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
.\.venv\Scripts\python.exe -m threat_platform download-ctu13
.\.venv\Scripts\python.exe -m threat_platform ingest-ctu13
.\.venv\Scripts\python.exe -m threat_platform verify-ingestion data/processed/ctu13-scenario11-v1
~~~

Then run the demonstration:

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.demo --data data/processed/ctu13-scenario11-v1 --version 1 --limit 2175 --output artifacts/demo-001
~~~

Use a new output directory each time. The CLI refuses overwrite. It first verifies that the service and selected registry record have identical version/fingerprint, then runs baseline/shifted replay, invalid-input validation, a 100-request individual benchmark, promotion rejection, a synthetic analyst case/review and a monitoring snapshot. It does not retrain or switch models. The new synthetic uncertain review intentionally persists in the case database.

## Read the output

| File | Meaning |
|---|---|
| summary.json | Identity, analyst review result, promotion decision and evaluation limits |
| replay.json | Frozen-threshold detection metrics on the unchanged selected development holdout |
| shifted.json | Drift and service measurements; detection suppressed after perturbation |
| benchmark.json | Sequential loopback individual-request throughput, p95 and failures |
| gate.json | Explicit production rejection and each policy check |
| monitor.json | Process-local service counters and rolling successful request latency |
| checksums.json | SHA-256 of the six JSON reports |
| README.md | Workload interpretation and cautions |

The report directory is published only after checks pass. A crash can leave a staging directory; no incomplete final report is advertised. HTTP case/review writes occur before report publication and are not rolled back if a later filesystem error occurs. Rerunning creates a new synthetic case, so avoid unnecessary reruns.

## Demonstrate failure behavior

1. Compare replay and shifted distributions without assuming drift proves attack.
2. Show that negative packet counts return 422 and leave the model ready.
3. Save a benign/uncertain analyst review and show that original model decisions do not change.
4. Present the rejected production gate, including missing independent/day coverage evidence.
5. In a separate simulation, activate a registered candidate and rollback using Step 9. Restart and show the expected fingerprint. Do not fabricate a second version just to label it better.
6. Explain how invalid runtime predictions remove readiness, while archived cases can remain accessible.
7. Stop/restart the container and inspect persisted cases. Monitoring counters reset; case records survive.

## Metrics and interpretation

Average precision and trapezoidal PR-AUC are separate fields. Recall is measured at the saved validation-selected threshold, with test FPR reported honestly. A 1% validation target is not a promise of 1% future/test FPR. False alerts per day remains null until continuous exposure and trustworthy benign labels are available.

Throughput and p95 depend on CPU, workers, batch size and workload; report them from your local run rather than quoting CI fixture timings as public-data results. A few repeated synthetic requests are functional evidence only. Do not claim GPU serving: training used a GPU, but the API reloads on CPU.

## Independent evaluation protocol — still required

Before any operational claim, obtain a new untouched capture with a suitable license and documented labels; reserve it before tuning. Pin raw and processed hashes, record UTC start/end and continuous observation intervals, define ambiguous/background handling, and compare host/session/content overlap with training. Keep labels and identifiers out of features.

Choose business costs, minimum support, target FPR and false-alert budget before opening results. Freeze preprocessing, model fingerprint and threshold. Evaluate a baseline and the candidate on the same independent events, report confidence intervals and class/prevalence counts, and review a sample manually. Report unsupported days as partial, not extrapolated full days. Preserve failures instead of selectively dropping them.

Current CTU adapter supports scenario 11 only; do not feed another capture through it by relabeling its identity or replacing pins. A new adapter and provenance contract are required. The development evaluation remains useful for regression testing, but the gate rejects production until this independent evidence path is implemented and reviewed.

## Verification and maintenance

See [verification](verification.md). CI unit/integration tests plus browser, operations and container smoke checks exercise the code. Numerical fixture training uses synthetic rows and is explicitly distinguished from public data. No user weights, ZIPs, cases or data are committed.

Keep artifacts/tracking, artifacts/analyst and deployment state backups on D drive. GitHub stores code and guides. Downloaded top-level model names are ignored as a safeguard; prefer storing new bundles under artifacts/. MLflow/PostgreSQL are optional future integrations; SQLite provides the implemented free path.

Further work is evidence-driven: independent capture adapter/evaluation, calibrated monitoring, authentication, provenance signing and operational review. Completing the demonstration does not remove these limitations.
