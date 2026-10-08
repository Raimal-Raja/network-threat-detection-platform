# Network threat-detection platform

An incremental project using free resources to ingest public network flows, train models and support analyst investigations. All replay workloads are **SIMULATED**. Steps 1–9 and the Step 10 demonstration are implemented and verified. Independent operational evaluation still requires a new untouched capture; no production approval is claimed.

## Learning guides

Each README progresses from basics through implementation, commands, tests, failures and advanced limitations.

1. [Foundation and event validation](docs/steps/01-foundation/README.md)
2. [Public-data ingestion and provenance](docs/steps/02-public-data/README.md)
3. [Features and chronological evaluation](docs/steps/03-features/README.md)
4. [Training, free Colab GPU and model saving](docs/steps/04-training/README.md)
5. [Local experiment tracking and model versions](docs/steps/05-tracking/README.md)
6. [FastAPI individual/batch inference and HTTP benchmarks](docs/steps/06-serving/README.md)
7. [Analyst dashboard, explanations and feedback](docs/steps/07-analyst/README.md)
8. [Simulated replay, drift and monitoring](docs/steps/08-replay/README.md)
9. [Deployment checks, simulation activation and rollback](docs/steps/09-deployment/README.md)
10. [End-to-end demonstration and independent evaluation protocol](docs/steps/10-demonstration/README.md)

[Open the Colab training notebook](https://colab.research.google.com/github/Raimal-Raja/network-threat-detection-platform/blob/main/notebooks/04_training_colab.ipynb). Free GPU availability varies; CPU works too. Download the ZIP before the runtime ends. No paid API is used.

Canonical local location: D:\GitHub\network-threat-detection-platform. Data and models stay in ignored data/ and artifacts/ directories. See [attribution](DATA_SOURCES.md).

## Local setup

Python 3.11+ is required. Steps 1–2 use the standard library; training uses requirements-training.txt. From the D-drive project folder:

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-service.txt
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

Both learned models missed the 1% test FPR target and are **not promoted**. Average precision and trapezoidal PR-AUC are distinguished in the training report. False alerts/day remain unmeasured without complete-day exposure. The [Step 10 public-data demo](docs/steps/10-demonstration/measured-example.json) replayed 2,175 test events without failures. Individual HTTP p95 was 32.27ms and throughput 56.60 requests/sec on an i5-1235U Windows laptop; batch replay throughput was 1,953.68 events/sec. These single-run simulated measurements are not a production SLA.

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
| 07 | Complete | Local analyst dashboard, exact TreeSHAP and append-only reviews |
| 08 | Complete | Simulated replay, traffic changes and monitoring |
| 09 | Complete | Container checks, promotion rejection and simulation rollback |
| 10 | Demo complete; independent evaluation pending | Measured report bundle and independent evaluation protocol |

Use local open-source tools as the free fallback. FastAPI, SQLite, Docker packaging and GitHub CI are implemented. MLflow/PostgreSQL are optional future integrations; no paid resource is provisioned. Every completed step receives its own README and verification evidence.

## Final verification

[CI verification](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707): 83 unit/API tests plus browser, operations and container persistence smoke checks passed. No model retraining is needed to use the new steps. Start the service using Step 7, then use Step 10 to generate your own report bundle.

---

## Setup and repository reference

### Project structure

- [DATA_SOURCES.md](DATA_SOURCES.md)
- [Dockerfile](Dockerfile)
- [compose.yaml](compose.yaml)
- [docs](docs)
- [notebooks](notebooks)
- [requirements-service.txt](requirements-service.txt)
- [requirements-training.txt](requirements-training.txt)
- [tests](tests)
- [threat_platform](threat_platform)

### Getting started

```bash
git clone https://github.com/Raimal-Raja/network-threat-detection-platform.git
cd network-threat-detection-platform
```

Create and activate a virtual environment, then install the project dependencies:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r "requirements-training.txt"
```

Open the relevant .ipynb notebook in Jupyter or a compatible notebook environment. Inspect its dependency and data-loading cells before running; there is no single shared application entry point.

### Configuration and limitations

Use the dependency manifests and workflow commands in the project sections above. Model/API tests use simulated fixtures; passing them does not establish production threat-detection accuracy or operational deployment readiness.

### Validation

Audit: 2026-10-08. Repository structure, setup instructions and description were reviewed. 29 existing Python files passed syntax checks; changed files and new regression tests were checked separately. 1 JavaScript files passed node --check; JSX/TypeScript production builds were not run. 83 regression tests passed. Syntax checks do not establish full runtime correctness. External APIs, live scraping, GUI interaction, notebook training and production deployment were not comprehensively exercised.

```bash
python -m unittest discover -s tests -v
```

### Repository description

The short GitHub description is provided in [REPOSITORY_DESCRIPTION.md](REPOSITORY_DESCRIPTION.md).

### Contributions

Describe the issue, reproduction steps, environment, and expected behavior when proposing a change. Keep generated environments, credentials, and unnecessary build artifacts out of new commits.

### License

No top-level license file was found during this review.
