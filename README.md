# Network threat-detection platform

An incremental project using free resources to ingest public network flows, train models and build a future analyst workflow. All replay workloads are **SIMULATED**. Steps 1–6 are complete. Local research inference is available; the analyst dashboard and production deployment are later milestones.

## Learning guides

Each README progresses from basics through implementation, commands, tests, failures and advanced limitations.

1. [Foundation and event validation](docs/steps/01-foundation/README.md)
2. [Public-data ingestion and provenance](docs/steps/02-public-data/README.md)
3. [Features and chronological evaluation](docs/steps/03-features/README.md)
4. [Training, free Colab GPU and model saving](docs/steps/04-training/README.md)
5. [Local experiment tracking and model versions](docs/steps/05-tracking/README.md)
6. [FastAPI individual/batch inference and HTTP benchmarks](docs/steps/06-serving/README.md)
7. [Analyst dashboard, explanations and feedback](docs/steps/07-analyst/README.md)

[Open the Colab training notebook](https://colab.research.google.com/github/Raimal-Raja/network-threat-detection-platform/blob/main/notebooks/04_training_colab.ipynb). Free GPU availability varies; CPU works too. Download the ZIP before the runtime ends. No paid API is used.

Canonical local location: D:\GitHub\network-threat-detection-platform. Data and models stay in ignored data/ and artifacts/ directories. See [attribution](DATA_SOURCES.md).

## Local setup

Python 3.11+ is required. Steps 1–2 use the standard library; training uses requirements-training.txt. From the D-drive project folder:

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-training.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m threat_platform download-ctu13
.\.venv\Scripts\python.exe -m threat_platform ingest-ctu13
.\.venv\Scripts\python.exe -m threat_platform verify-ingestion data/processed/ctu13-scenario11-v1
.\.venv\Scripts\python.exe -m threat_platform.training --data data/processed/ctu13-scenario11-v1 --output artifacts/local-001 --device cpu --target-fpr 0.01
~~~

Skip ingestion if the existing run verifies; use a new training output name. Source/processed checksums are verified before fitting. Saved bundles contain features, hashes, versions, thresholds, metrics and audits, and are reloaded on CPU before publication.

## Measured results

The [verified T4 run](docs/steps/04-training/verification.md) passed 38 tests. Validation recommended logistic regression. An XGBoost research bundle was exported and reloaded on CPU.

| Model | Test average precision | Recall | False alerts / benign | Test FPR |
|---|---:|---:|---:|---:|
| Dummy | 0.824368 | 0% | 0 / 382 | 0% |
| Logistic regression | 0.999996 | 99.944% | 6 / 382 | 1.571% |
| XGBoost GPU | 0.999991 | 100% | 24 / 382 | 6.283% |

Both learned models missed the 1% test FPR target and are **not promoted**. Average precision and trapezoidal PR-AUC are distinguished in the training report. False alerts/day remain unmeasured. Step 6 adds local HTTP throughput and p95 measurement; its smoke-test results use a separate synthetic model fixture and do not represent this public-data model.

This short capture shares hosts across periods and excludes unknown labels, creating unusually high suspicious prevalence. Its test period was already inspected and is a development holdout. Reserve a new independent capture for final evaluation; these scores do not establish operational effectiveness.

## Incremental roadmap

| Step | Status | Deliverable |
|---|---|---|
| 01 | Complete | Event contract, fixtures, validation |
| 02 | Complete | Pinned CTU-13 ingestion and provenance |
| 03 | Complete | Six features, completion-time splits and overlap audits |
| 04 | Complete | Baselines, GPU/CPU training and portable export |
| 05 | Complete | SQLite experiment ledger, verified snapshots and model versions |
| 06 | Complete | Pinned-version FastAPI inference, strict validation and HTTP benchmarks |
| 07 | Under verification | Local analyst dashboard, exact TreeSHAP and append-only reviews |
| 08 | Planned | Simulated replay, traffic changes and monitoring |
| 09 | Planned | Deployment checks, promotion rejection and rollback |
| 10 | Planned | End-to-end demonstration and independent evaluation |

Use local open-source tools as the free fallback. Later milestones can add self-hosted MLflow, FastAPI, PostgreSQL, Docker and CI without provisioning paid resources. Every completed step receives its own README and verification evidence.
