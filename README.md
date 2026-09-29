# Network threat-detection platform

A step-by-step project for learning reproducible machine learning and operating a threat-detection service. All replay workloads are **SIMULATED**. **Steps 1 and 2 are complete**: synthetic fixtures and reproducible public-data ingestion. The project does not yet predict threats or provide a production service.

## Start here

Start with [Step 1 — foundation, event contract, and validation](docs/steps/01-foundation/README.md), then [Step 2 — public-data ingestion and provenance](docs/steps/02-public-data/README.md). Each guide explains concepts, implementation, commands, failure cases, limitations, and exercises from beginner through advanced level.

Requirements: Python 3.11 or newer. Both completed steps have **zero third-party dependencies**. Step 2 needs internet access once to download a 14.6 MB public flow CSV. No API key, paid account, GPU, or Docker installation is required. Verification records accompany each step.

From this directory:

```powershell
python -m unittest discover -s tests -v
python -m threat_platform generate --output data/demo.jsonl --count 1000 --seed 42
python -m threat_platform validate data/demo.jsonl
```

Generation refuses to overwrite an existing dataset. Use a new filename to run another experiment. If `python` is unavailable, see the Windows instructions in the Step 1 README.

For public data:

```powershell
python -m threat_platform download-ctu13
python -m threat_platform ingest-ctu13
python -m threat_platform verify-ingestion data/processed/ctu13-scenario11-v1
```

The downloader checks a pinned SHA-256 before accepting a source. Raw data and processed event files stay local under ignored `data/`; source code, tests, learning guides, and a compact example manifest belong in Git. See Step 2 for TLS certificate troubleshooting, label policy, attribution, and why this short capture is not a benchmark.

## Incremental delivery plan

Every completed step gets a `docs/steps/NN-topic/README.md` containing: prerequisites, basic concepts, architecture, code walkthrough, reproducible commands, verified results, failure cases, advanced tradeoffs, and exercises. Planned steps are not implemented features.

| Step | Scope | Completion evidence |
|---|---|---|
| 01 — complete | Foundation, simulated generator, strict event validation | Deterministic bytes, validation failures, CLI and unit tests |
| 02 — complete | Public-data ingestion and provenance | Pinned CTU-13 source, checksums, attribution, UTC conversion, exclusion accounting, verified manifest |
| 03 | Features and chronological evaluation splits | Feature allowlist, train-only preprocessing, duplicate/group-overlap audits, temporal boundaries |
| 04 | Baseline and stronger model | Dummy baseline, logistic regression, histogram gradient boosting; untouched test results |
| 05 | Experiments and model versions | Local MLflow records, data/code/config hashes, artifact and schema versions |
| 06 | FastAPI inference | Individual and batch requests, validation, health/readiness, benchmark harness |
| 07 | Analyst workflow | Alerts, explanations, feedback, PostgreSQL persistence and dashboard |
| 08 | Replay and monitoring | Explicit simulated clock, drift scenarios, invalid-input rate, throughput, p95 latency |
| 09 | Deployment and rollback | Reproducible container, checks, promotion gate, rejected bad model, rollback drill |
| 10 | Portfolio demonstration | End-to-end replay, final report, limitations, reproducibility instructions |

## Budget and tools

Use local execution as the default so completion never depends on promotional cloud credits. Step 1 uses only Python. Later phases will use scikit-learn, FastAPI, local PostgreSQL, local MLflow, and a simple open-source dashboard. A CPU-friendly histogram gradient-boosting model avoids a GPU requirement; XGBoost is optional if a measured comparison justifies it.

Containerization and hosted CI come later. Local tests remain the authoritative free fallback. Review the applicable license and current account limits before enabling Docker Desktop or hosted CI; neither is needed for Step 1. No paid resource has been provisioned. Running on your own machine still consumes storage, electricity, and compute time.

Useful free learning references:

- [Python tutorial](https://docs.python.org/3/tutorial/) — language and modules.
- [Python unittest](https://docs.python.org/3/library/unittest.html) — automated tests.
- [CTU-13 official dataset page](https://www.stratosphereips.org/datasets-ctu13) — selected source; see [attribution](DATA_SOURCES.md).
- [CICIDS2017 official dataset page](https://www.unb.ca/cic/datasets/ids-2017.html) — possible later extension; not downloaded.
- [scikit-learn user guide](https://scikit-learn.org/stable/user_guide.html) — pipelines, models, metrics.
- [FastAPI tutorial](https://fastapi.tiangolo.com/tutorial/) — later serving layer.
- [MLflow self-hosting](https://mlflow.org/docs/latest/self-hosting) — later local tracking.
- [PostgreSQL tutorial](https://www.postgresql.org/docs/current/tutorial.html) — later persistence.

## Evaluation commitments

Accuracy alone is unsuitable for rare alerts. Step 4 will report average precision (explicitly distinguish it from trapezoidal PR-AUC), recall at a validation-selected threshold targeting a fixed false-positive rate, the achieved test false-positive rate, and false alerts per observed replay day. Select thresholds and models using validation data only; keep the final time period untouched until evaluation.

False alerts per day depend on benign traffic volume and the replay clock. Report both the clock definition and denominator. Do not scale this tiny synthetic fixture into operational claims. Service benchmarks will disclose hardware, batch size, concurrency, warmup, test duration, throughput, error rate, and p95 latency. Performance metrics are **not measured yet**.

## Current boundary

Step 2 ingests one short public capture for simulated replay. It does not establish real-world security effectiveness, solve train/test leakage, provide authentication, or collect live traffic. Next is Step 3: feature definitions and honest chronological evaluation. Before modelling, check whether time periods contain both classes and whether shared hosts or capture artifacts would make evaluation misleading. More captures may be required; do not force a random split to hide those problems.
