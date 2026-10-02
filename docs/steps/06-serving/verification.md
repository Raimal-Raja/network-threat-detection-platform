# Step 6 verification — 2026-10-02

All 57 repository tests passed in 5.703 seconds on Python 3.12.14. This includes ten new API tests and three benchmark tests, plus all 44 existing tests. Dependencies match requirements-service.txt.

## Functional evidence

API tests load an actual XGBoost bundle trained on 120 synthetic completed-flow rows. Only ingestion provenance is mocked to isolate service behavior; existing ingestion tests exercise real checksum verification. HTTP scores and alert decisions match offline inference. Tests cover strict numbers/protocols, unknown fields, malformed/nonfinite JSON, batch bounds and atomic validation, the received-byte limit despite a false Content-Length, health/readiness/model details, corrupted and unknown versions, incompatible features, pinned running versions and invalid runtime scores.

Benchmark tests use a separate synthetic-response HTTP server to check event throughput arithmetic, all-failure accounting and invalid configurations.

## Actual Uvicorn HTTP smoke benchmark

A separate actual fixture model was trained, registered and loaded into Uvicorn on loopback. Readiness returned 200 with version 1, CPU serving, simulated=true and production_ready=false. One server worker, XGBoost n_jobs=2, 12 reported logical CPUs; CPU model was unavailable from the runtime. Windows-11-10.0.29639-SP0.

Both runs used 50 measured requests after 5 warmup requests, concurrency 1 and repeated synthetic inputs. Warmup/readiness were excluded.

| Request shape | Successful requests/s | Events/s | p95 request latency | Errors | Timed duration |
|---|---:|---:|---:|---:|---:|
| One flow | 68.01 | 68.01 | 28.58 ms | 0 / 50 | 0.7351 s |
| Batch of 32 | 61.26 | 1960.22 | 30.18 ms | 0 / 50 | 0.8162 s |

These short smoke runs demonstrate the measurement path, not a stable SLO, sustained load result or throughput guarantee. Batch p95 is per request, not per event. Standard urllib includes connection overhead. The hardware description is incomplete because the CPU model was unavailable.

[Full measurements and environment](benchmark-example.json). This fixture model is separate from the public CTU-13 run and the user's saved Colab bundle. These latency results must not be attached to its detection metrics as though measured on the same workload. False alerts/day and drift remain unmeasured.

## Delivery boundary

The API serves a research candidate and does not provide authentication, production promotion, public deployment, analyst persistence or rollback. D-drive writes returned EPERM despite granted access, so GitHub is published and the user must git pull to synchronize locally. Temporary testing files and the loopback server are removed after verification.
