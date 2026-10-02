# Step 6 — FastAPI individual and batch inference

## Outcome and prerequisites

This step serves the Step 4 XGBoost model through a local HTTP API after verifying its Step 5 registry snapshot. It supports one completed flow or a batch, pins the model version, validates inputs, and exposes health/readiness and model details. The workload remains **SIMULATED** and **production_ready=false**. An API being ready means inference works; it does not mean the detector met its security performance target.

You need Python 3.11+, a downloaded/unzipped model bundle, and the [Step 5](../05-tracking/README.md) registration commands. A GPU, paid cloud service, API key and Docker are unnecessary. The service predicts on CPU.

## Basic concepts

HTTP is a request/response protocol. A client sends JSON to an endpoint; the server validates it and returns JSON with a status code. POST requests carry prediction inputs. GET endpoints inspect the process or model. FastAPI defines endpoints and generates OpenAPI documentation; Pydantic checks the data contract; Uvicorn runs the server.

Training learns model parameters. Inference uses those frozen parameters. This API does not train models, choose thresholds from requests, or inspect caller-provided labels.

## Setup on D drive

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
git pull --ff-only origin main
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-service.txt
~~~

Reuse an existing .venv rather than recreating it if it already contains your project environment. Stop on installation errors. requirements-service.txt includes the training requirements and tested API dependencies.

Unzip your Colab archive. If extracted into artifacts/colab-download, its model directory is artifacts/colab-download/model:

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.tracking register --bundle artifacts/colab-download/model --note "Colab research model"
.\.venv\Scripts\python.exe -m threat_platform.tracking list
~~~

Use the version number returned by registration; it may not be 1. The following example assumes version 1:

~~~powershell
$env:THREAT_MODEL_STORE = "D:\GitHub\network-threat-detection-platform\artifacts\tracking"
$env:THREAT_MODEL_VERSION = "1"
.\.venv\Scripts\python.exe -m uvicorn threat_platform.api:app --host 127.0.0.1 --port 8000 --workers 1
~~~

Keep that terminal open. Open http://127.0.0.1:8000/docs in your browser for interactive request documentation. Use a second PowerShell terminal for requests. Stop the server with Ctrl+C.

This is a loopback research service. There is no authentication, TLS, rate limiting or public deployment in this milestone. Keep the documented loopback binding; deployment controls belong to a later step. Swagger's browser assets may require internet access even though inference itself runs locally.

## Endpoints and statuses

| Endpoint | Purpose |
|---|---|
| GET /health | Process liveness; 200 even when the model failed to load |
| GET /ready | 200 when the pinned model loaded and warmed up; otherwise 503 |
| GET /model | Version, hashes, threshold, evaluation status and test results |
| POST /predict | One validated completed flow |
| POST /predict/batch | 1–256 flows, with all-or-nothing validation |
| GET /docs | Interactive OpenAPI documentation |

Successful predictions return 200. Invalid JSON/schema returns 422. Prediction bodies above 65,536 bytes return 413. Missing/failed models return 503. These codes distinguish caller input problems from unavailable inference.

## Individual prediction

~~~powershell
$flow = @{ duration_us = 1000; packets = 12; bytes = 4096; protocol = "TCP" }
$body = $flow | ConvertTo-Json -Compress
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict -Method Post -ContentType "application/json" -Body $body
~~~

The response includes suspicious_score, alert, threshold, model_version, bundle_sha256, feature_version, simulated and production_ready. alert means score >= the saved validation-selected threshold. Scores are not guaranteed calibrated probabilities.

Only four fields are accepted. Duration is an integer in microseconds, from 0 to one day. Packet/byte counts are nonnegative signed 64-bit integers. Protocol is exactly TCP, UDP or ICMP. Strings masquerading as numbers, floats, booleans, unknown fields and labels fail. Measurements describe completed flows; this is not early detection while a flow is still running.

## Batch prediction and failures

~~~powershell
$body = @{ events = @($flow, $flow) } | ConvertTo-Json -Depth 4 -Compress
Invoke-RestMethod -Uri http://127.0.0.1:8000/predict/batch -Method Post -ContentType "application/json" -Body $body
Invoke-RestMethod -Uri http://127.0.0.1:8000/ready
Invoke-RestMethod -Uri http://127.0.0.1:8000/model
~~~

Results preserve input order. Empty batches and more than 256 events fail. If one event is invalid, the entire request fails rather than returning partial predictions. Duplicate measurements are allowed for inference; training duplicate audits are a separate concern.

The body limit counts actual received bytes before JSON parsing, including chunked requests, instead of trusting Content-Length. Batch count and byte limits are separate: a batch within 256 rows can still exceed the byte limit.

Validation errors do not echo raw request inputs. Server logs contain startup/inference diagnostics; HTTP errors do not reveal local paths. No request-event persistence is implemented yet.

## Startup and model integrity

The FastAPI lifespan handler runs before requests are served. It resolves the explicitly requested registry version, verifies all eight snapshot files against the stored report, validates feature version/order, rereads model bytes and checks their hash, and loads the bytes into XGBoost on CPU. It checks the model has six inputs and a binary-logistic objective, then warms up the prediction path.

The model is loaded once rather than for every request. Version and threshold are fixed for the process lifetime. Registering a newer version does not silently switch an existing service. Restart with a different THREAT_MODEL_VERSION to intentionally select it; automated promotion and rollback remain later work.

Readiness describes the in-memory model. File changes after startup do not change that already-loaded model; a subsequent startup verifies disk again. Checksums are not artifact signatures and depend on a trusted registry.

Synchronous prediction routes use FastAPI's worker thread pool. A lock serializes calls into the shared XGBoost model; n_jobs=2 bounds its internal CPU parallelism. Multiple Uvicorn workers would each load a model and need separate benchmarking; the demonstrated configuration uses one worker.

If inference raises or returns invalid/nonfinite scores, the API responds 503 and removes readiness until restart. It does not continue emitting potentially invalid alerts.

## Measure throughput and p95 latency

The standard-library benchmark sends synthetic completed-flow JSON over actual local HTTP. Run it in the second terminal while the server is ready:

~~~powershell
.\.venv\Scripts\python.exe -m threat_platform.benchmark --requests 200 --warmup 20 --batch-size 1 --output artifacts/http-single-001.json
.\.venv\Scripts\python.exe -m threat_platform.benchmark --requests 200 --warmup 20 --batch-size 32 --output artifacts/http-batch32-001.json
~~~

Each output records UTC time, model identity, endpoint, requests, warmup, batch size, concurrency=1, elapsed time, errors, error rate, successful requests/second, events/second and p95 successful request latency. Warmup and readiness probes are excluded from timing. Throughput includes time spent on failures; latency only includes successful requests. Any measured failures cause a nonzero command exit.

p95 uses the nearest-rank 95th percentile of observed successful request times. Batch latency is time for one batch request, not per-event latency. The client uses standard urllib HTTP requests, including connection overhead; this is not a keep-alive or high-concurrency load generator.

Record server hardware, CPU configuration, workers and packages beside results. Results depend on hardware and workload and do not establish an operational SLO. False alerts per day and drift require later replay scenarios; repeating a synthetic flow measures service performance rather than detection quality.

See [verification](verification.md) for actual tests and any measured smoke-benchmark results. The user's trained Colab model must still be supplied locally; test fixtures are not its evaluation.

## Tests and advanced tradeoffs

~~~powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
~~~

API tests use a real small XGBoost bundle trained on simulated fixture rows. They compare HTTP single/batch output with offline inference, check strict validation and limits, exercise health/readiness, detect corrupted startup, pin versions and inject a runtime output failure. Existing ingestion tests separately verify genuine source checksums.

The test training fixture mocks only ingestion provenance to isolate service behavior. Its detection metrics are not benchmark claims. Unit/HTTP contract correctness cannot establish security effectiveness. Both learned models in the Step 4 public-data run missed their test FPR target; this API does not change that result.

Future work includes authentication and request policy, monitoring, concurrent load tests, alert persistence, analyst explanations/feedback, independent evaluation, deployment checks and rollback. There is no MLflow integration or public hosting in this milestone.

## Exercises

1. Send a quoted packet count and explain the 422 response.
2. Send a batch with one invalid row and verify no partial result.
3. Start with an unknown model version and compare /health with /ready.
4. Compare batch size 1 with 32 using the same model and hardware.
5. Register another version and verify the running API still reports its pinned version.

Next: Step 7, analyst alerts, explanations and feedback.

Primary references: [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/), [FastAPI testing](https://fastapi.tiangolo.com/tutorial/testing/), [Pydantic strict validation](https://pydantic.dev/docs/validation/latest/concepts/strict_mode/).
