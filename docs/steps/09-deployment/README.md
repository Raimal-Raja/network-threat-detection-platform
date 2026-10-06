# Step 9 — Deployment checks, simulation activation and rollback

## Outcome

This milestone packages the local service in Docker, checks candidate models before activation, stores active-version history, rejects unsupported production promotion and restores the previous verified version. It remains **SIMULATED** and **production_ready=false**. Docker is optional; ordinary Python is the free fallback.

## Basic concepts

Registration inventories immutable bundles. Activation selects what the next process starts with. Promotion requires evidence that a candidate meets quality and operational policy. Rollback restores a previous version when a candidate is worse or fails. These are separate actions.

A running service remains pinned. Changing activation state does not silently swap its model. Restart deliberately after activation or rollback and inspect /ready for the expected version and fingerprint.

## Benchmark and production gate

Run this against the already-running version 1 service:

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
.\.venv\Scripts\python.exe -m threat_platform.benchmark --requests 200 --warmup 20 --output artifacts/deployment/benchmark-001.json
.\.venv\Scripts\python.exe -m threat_platform.deployment gate 1 --benchmark artifacts/deployment/benchmark-001.json --output artifacts/deployment/gate-001.json
~~~

The gate writes a JSON decision and intentionally exits 1 when rejecting. Rejection is the expected result for the current CTU model, not a crash. The model's test FPR was about 6.28%, above the 1% target.

Default checks require FPR <=1%, recall >=90%, >=1,000 benign and >=100 suspicious evaluation examples, a matching benchmark fingerprint/version, >=100 completely successful requests, p95 <=100ms and >=1 event/second. These are illustrative policy values, not business-approved operational budgets.

The current bundle contract cannot certify an untouched independent capture or complete-day exposure. Both checks therefore fail closed, even if somebody edits evaluation_status to say independent. This code cannot grant production approval. Real promotion needs a new evidence contract with audited disjoint captures, label provenance, exposure intervals, signed/approved evaluations and a chosen alert budget.

A CLI gate compares the exported XGBoost test record with benchmark evidence; it does not certify the truth of manually edited metrics. Registry checksums detect changes against the ledger, not forgery by a person controlling both ledger and files.

## Activate for local simulation

Stop the server before changing the version you intend to serve. Use status to obtain the latest revision:

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.deployment status
.\.venv\Scripts\python.exe -m threat_platform.deployment activate 1 --expected-revision 0 --simulation
~~~

Revision 0 means no active state yet. If already initialized, use the returned revision rather than repeating 0. Activation loads the checksum-verified model on CPU and verifies a prediction/explanation before mutating SQLite state. It requires --simulation explicitly and does not override gate rejection.

Start from activation state rather than an explicit version:

~~~powershell
Remove-Item Env:THREAT_MODEL_VERSION -ErrorAction SilentlyContinue
$env:THREAT_MODEL_STORE = "D:\GitHub\network-threat-detection-platform\artifacts\tracking"
$env:THREAT_DEPLOYMENT_DB = "D:\GitHub\network-threat-detection-platform\artifacts\deployment\state.sqlite3"
$env:THREAT_CASE_DB = "D:\GitHub\network-threat-detection-platform\artifacts\analyst\cases.sqlite3"
.\.venv\Scripts\python.exe -m uvicorn threat_platform.api:app --host 127.0.0.1 --port 8000 --workers 1
~~~

An explicit THREAT_MODEL_VERSION takes precedence when set. Check /ready to confirm identity; /health alone confirms process liveness, not a usable model.

## Rollback example

If a second registered candidate exists, simulation activation of version 2 at revision 1 advances to revision 2. To restore the previous version:

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.deployment rollback --expected-revision 2 --simulation
~~~

Use your actual revision. The command verifies the previous bundle and CPU smoke check before switching. Unknown/corrupt models and stale revisions leave active state unchanged. Store paths must match; a state database cannot silently redirect another registry.

State changes use BEGIN IMMEDIATE and append a history row. Optimistic revision checks prevent concurrent operators from overwriting a newer selection. Rollback targets the immediately preceding history version. It is not hot reload or zero-downtime orchestration; restart the process and verify /ready afterward. Archived analyst cases retain their original model snapshots.

## Docker option

Install/start Docker separately if you choose this option. Export a verified container-readable copy of your selected version first. The source registry remains private; the explicit export uses readable file/directory permissions and preserves version/fingerprint. Choose a new output directory if an export already exists; point Compose at that directory before updating the container.

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.deployment export-model 1 --output artifacts/container-models
$env:THREAT_MODEL_VERSION = "1"
docker compose up --build -d
docker compose ps
docker compose logs --tail 50 analyst
~~~

Open http://127.0.0.1:8000/analyst. Stop an existing native server first to free port 8000. Compose binds the host port to loopback, mounts exported model files read-only and keeps cases in a named volume. The image runs as UID 10001 with a read-only root filesystem, temporary /tmp, dropped capabilities and readiness health check.

~~~powershell
docker compose down
~~~

This stops/removes the container while preserving the named case volume. Do not add --volumes unless you intend to delete those saved cases. Back up native cases separately; Docker's named volume does not automatically reuse the native SQLite file.

Dockerfile uses a Python 3.12-slim tag and pinned Python dependencies. The base tag/system packages are mutable; record the built image ID, scan/update it and pin a reviewed digest for an actual release. No registry push or cloud deployment is configured. Docker Desktop licensing eligibility depends on your use; the Linux Docker Engine/ordinary Python paths avoid assuming a paid plan.

## Verification and advanced limitations

See [verification](verification.md). Tests demonstrate stale-revision rejection, failed activation preserving state, corrupt rollback refusal, explicit-version precedence, a worse candidate rejected by recall, and continued pinned serving. CI builds the actual image, checks Compose syntax, serves a synthetic model and verifies a saved case survives container restart.

This local prototype lacks authentication, signed artifact provenance, multiuser access control, distributed locks, rolling deployment and real incident response. Do not expose the loopback dashboard publicly without implementing those controls.

Next: [Step 10 end-to-end demonstration](../10-demonstration/README.md).
