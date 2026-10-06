# Step 7 — Analyst dashboard, explanations and feedback

## Outcome and prerequisites

This milestone adds a local analyst workspace to the Step 6 FastAPI service. You can assess a completed flow, save its original prediction and exact TreeSHAP explanation, filter the investigation queue, append a review and export a case. Everything remains **SIMULATED** and **production_ready=false**.

Complete [Step 6](../06-serving/README.md), download your Colab model, and register it using Step 5. No retraining is required. This milestone adds no service packages: the existing XGBoost, FastAPI and Python SQLite libraries suffice. The dashboard uses local HTML/CSS/JavaScript without a CDN, paid API, frontend build service or extra database server.

## Basic concepts

A model alert is a threshold-based decision. A case is an archived investigation record, whether the model alerted or not. Analyst feedback is a separate judgment: suspicious, benign or uncertain. A benign review of an alerted case suggests a possible false positive, but a self-reported review is not automatically verified ground truth.

Persistence means records survive process restarts. An immutable prediction snapshot lets you see what the original model said even after a new model version exists. An append-only review history preserves previous judgments instead of replacing them.

## Start on D drive

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
git pull --ff-only origin main
.\.venv\Scripts\python.exe -m pip install -r requirements-service.txt
.\.venv\Scripts\python.exe -m threat_platform.tracking list
~~~

If your project has no virtual environment yet, follow the Step 6 setup first. If you have not registered the model, use the Step 5 guide. Substitute the version returned by your registry rather than assuming it is 1:

~~~powershell
$env:THREAT_MODEL_STORE = "D:\GitHub\network-threat-detection-platform\artifacts\tracking"
$env:THREAT_MODEL_VERSION = "1"
$env:THREAT_CASE_DB = "D:\GitHub\network-threat-detection-platform\artifacts\analyst\cases.sqlite3"
.\.venv\Scripts\python.exe -m uvicorn threat_platform.api:app --host 127.0.0.1 --port 8000 --workers 1
~~~

Open http://127.0.0.1:8000/analyst. Keep the terminal open; stop it with Ctrl+C. Saved cases and reviews remain in the SQLite file under ignored artifacts/. Code and guides belong in GitHub; user cases, review notes, datasets and model weights stay local.

## Walk through the analyst workflow

1. Check the status panel. Both the model and case storage must be available to assess a flow.
2. Enter a unique event ID and completed-flow duration, packet count, byte count and protocol. Defaults are synthetic example measurements, not a claim that any real traffic is suspicious.
3. Select Assess & save. The server scores the flow, computes its explanation and saves both together.
4. Inspect the score, threshold, original model decision, model version and bundle fingerprint.
5. Read feature contributions alongside the measurements. Seek external capture evidence before making a security judgment.
6. Enter a reviewer alias, verdict and evidence note; select Save review.
7. Reload the page or restart the server. The saved case and its history remain.
8. Filter by review status or model alerts. Export JSON when you need the full archived case.

The browser generates a new event ID after successful assessment. Retrying the same ID and identical measurements under the same bundle returns the existing case. Reusing the ID with changed measurements returns 409 instead of overwriting it. The same source event assessed under a different bundle gets a separate case.

## Understand the explanation from basic to advanced

TreeSHAP distributes the model's raw output between a bias term and feature contributions. XGBoost computes exact tree contributions internally; the Python shap package is not needed.

For this binary-logistic model:

~~~text
raw margin = bias + sum(feature contributions)
model score = sigmoid(raw margin)
sigmoid(z) = 1 / (1 + exp(-z))
~~~

Contributions are in **log-odds**, not percentages or direct probability changes. Positive values push the score upward; negative values push it downward. The server checks that their sum matches the raw margin and that sigmoid reconstructs the prediction score within tolerance.

The features are the Step 3 log1p duration, packet and byte measurements plus TCP/UDP/ICMP indicators. The dashboard shows transformed feature values in contribution tooltips and preserves original counts separately. A packet contribution is attributed to the encoded log1p feature, not a causal claim about changing one packet.

Correlated inputs and the model's training distribution affect attribution. Contributions explain this model's output; they do not prove malicious intent, replace forensic evidence, or establish generalization to new networks. Exact tree attribution is not a guarantee that the model itself is correct.

## Persistence and concurrency

threat_platform/cases.py uses SQLite with parameterized SQL and foreign keys. The cases table stores event identity, model fingerprint, exact original input JSON, prediction/explanation snapshots, receipt time, alert flag and review revision. The receipt timestamp is not an invented traffic timestamp.

The feedback table stores case ID, sequential revision, reviewer alias, verdict, note and UTC review time. Previous reviews and the original prediction remain unchanged.

A BEGIN IMMEDIATE transaction serializes writers. Feedback includes expected_revision; if another reviewer saved first, the server returns 409. Refresh the selected case, inspect the newer review, and resubmit deliberately. The UI preserves note text after a conflict.

Queue pages return bounded summaries, not every explanation and review note. Full detail/export includes the history. SQLite fits this single-machine learning milestone. PostgreSQL is not implemented here; it is a future option when multiple users, larger workloads or deployment justify it.

## API examples

The original /predict and /predict/batch endpoints remain stateless. Only the explicit case endpoint saves an investigation:

~~~powershell
$payload = @{
  event_id = "demo-001"
  flow = @{ duration_us = 1000; packets = 104; bytes = 8200; protocol = "TCP" }
} | ConvertTo-Json -Depth 4
$case = Invoke-RestMethod -Uri http://127.0.0.1:8000/cases -Method Post -ContentType "application/json" -Body $payload
$case.id
~~~

Append a review using the current revision:

~~~powershell
$review = @{
  expected_revision = $case.revision
  reviewer = "local-analyst"
  verdict = "uncertain"
  note = "Need more capture evidence."
} | ConvertTo-Json
Invoke-RestMethod -Uri ("http://127.0.0.1:8000/cases/" + $case.id + "/feedback") -Method Post -ContentType "application/json" -Body $review
~~~

| Endpoint | Purpose |
|---|---|
| GET /analyst | Local dashboard |
| GET /analyst/status | Separate model/storage readiness |
| POST /cases | Assess, explain and save one case |
| GET /cases | Filtered summaries, pagination up to 100 cases/page |
| GET /cases/{id} | Original measurements, model snapshot and full history |
| POST /cases/{id}/feedback | Append a review with revision check |

Invalid schema or overlong notes return 422; missing cases return 404; conflicting retries/stale revisions return 409; bodies over 65,536 bytes return 413; unavailable model/storage returns 503. Cross-origin browser writes are rejected. Reviewer aliases are self-reported and do not provide authentication.

## Failure behavior and boundaries

A failed explanation produces no partial case and removes model readiness. A database failure does not masquerade as a successful save. If a new model fails startup, previously saved cases and feedback remain readable when storage is healthy. Stateless predictions do not require case storage.

All submitted flows obey the Step 6 strict contract; event IDs are restricted to a short safe identifier alphabet, reviewer aliases to 80 characters and notes to 2,000. The browser uses JavaScript-safe integers (up to 2^53-1 for packet/byte counts); the API supports the existing signed 64-bit limits. The UI receives exact counts as display strings, and JSON export downloads the raw server response to avoid rounding large integers.

Notes and identifiers are rendered with textContent rather than injected HTML. Assets are served from the same local origin with a content security policy. This is still a loopback prototype, without authentication, role-based authorization, signed audit records or public deployment. A user who can edit the database can alter its contents; append-only application routes are not a tamper-proof audit system.

Feedback is not automatically used for training, calibration, promotion or model switching. A future training pipeline must review label quality, account for selective analyst attention, preserve provenance and reserve an independent evaluation set. Only investigating model alerts creates selection bias and misses false negatives.

## Testing and verification

See [verification](verification.md) for actual execution evidence.

~~~powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
~~~

The new storage tests exercise restarts, idempotency, conflicting data, stale revisions, concurrent reviews, literal notes and exact large-integer display. Integration tests load a real synthetic XGBoost model, verify SHAP additivity and score reconstruction, preserve original decisions during reviews, reject invalid writes and exercise model failures and version changes.

Optional browser verification:

~~~powershell
.\.venv\Scripts\python.exe -m pip install playwright==1.55.0
.\.venv\Scripts\python.exe -m playwright install chromium
.\.venv\Scripts\python.exe tests/browser_smoke.py
~~~

The browser test trains a tiny synthetic fixture, starts a temporary loopback service, assesses a flow, records literal text resembling HTML, reloads/filter cases, and produces desktop/mobile screenshots under artifacts/verification. It does not read or submit your traffic.

The GitHub Actions workflow runs tests on a standard public-repository Linux runner, with read-only repository permissions and pinned official action revisions. No secrets or paid compute service are configured. Browser proof artifacts have a seven-day retention period. Local execution remains available independently of hosted CI.

## Backups and exercises

Stop the server before copying cases.sqlite3 for a simple local backup. Keep the model registry backup separately. For live backups or concurrent deployment, use SQLite's backup API and test restoration; a screenshot is not a database backup.

1. Review an alerted synthetic case as benign and confirm the original alert stays true.
2. Submit the same event twice, then change its bytes and explain the 409 response.
3. Open a case in two browser windows and trigger a stale-revision conflict.
4. Sum the contributions and reconstruct the score using sigmoid.
5. Restart with an unavailable version and inspect the archived review history.
6. Design a label-quality protocol before feeding analyst reviews into future training.

Next: Step 8, public-data replay, traffic changes and monitoring.

Primary references: [XGBoost Booster prediction API](https://xgboost.readthedocs.io/en/stable/python/python_api.html#xgboost.Booster.predict), [Python SQLite](https://docs.python.org/3/library/sqlite3.html), [Playwright Python](https://playwright.dev/python/docs/intro).
