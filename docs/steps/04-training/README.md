# Step 4 — Training, evaluation and saving models

## Outcome and prerequisites

After [Step 3](../03-features/README.md), train a dummy baseline, logistic regression and XGBoost. Select thresholds with validation data, measure later traffic, and export an XGBoost bundle that reloads on CPU. This is a SIMULATED research workload; the model is not promoted for production. All tools are free and no paid API is used.

## Basic models

DummyClassifier predicts the training suspicious prevalence. It checks whether learning adds value. Logistic regression learns weighted standardized features; StandardScaler fits on training only. XGBoost combines trees that correct earlier errors and capture nonlinear relationships. GPU execution changes computation, not data validity. CPU works for this small dataset.

Configurations are fixed for the reported run. Validation average precision recommends a model. XGBoost is exported even when logistic regression is recommended; export does not imply a win or deployment approval.

## Free Colab workflow

[Open the project notebook](https://colab.research.google.com/github/Raimal-Raja/network-threat-detection-platform/blob/main/notebooks/04_training_colab.ipynb). Save a notebook copy to Drive if desired. Choose Runtime → Change runtime type → T4 GPU when available. Run setup, tests/ingestion, training and ZIP export in order. If a free GPU is unavailable, set DEVICE to cpu.

Free GPU availability and session lifetime vary; see the [official FAQ](https://research.google.com/colaboratory/faq.html). No upgrade is necessary. /content files disappear when the runtime ends. Saving the notebook to Drive does not save the model automatically. Download the ZIP, save it under D:\GitHub\network-threat-detection-platform\artifacts, and unzip it before inference.

The previous NumPy/SciPy error arose after installed packages changed while the kernel retained older imports. This notebook installs packages and runs tests/training in fresh Python processes. If you instead import these packages directly into a kernel after reinstalling, restart the runtime first. 'model not defined' is a consequence of the earlier failed cell, not a second training fix.

The notebook prints its repository commit, uses pinned requirements, verifies data and writes unique output names. Explicit cuda training fails if XGBoost actually falls back to CPU.

## Local D-drive commands

From D:\GitHub\network-threat-detection-platform:

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-training.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m threat_platform download-ctu13
.\.venv\Scripts\python.exe -m threat_platform ingest-ctu13
.\.venv\Scripts\python.exe -m threat_platform verify-ingestion data/processed/ctu13-scenario11-v1
.\.venv\Scripts\python.exe -m threat_platform.training --data data/processed/ctu13-scenario11-v1 --output artifacts/local-001 --device cpu --target-fpr 0.01
~~~

Skip download/ingestion if an existing run verifies. Choose another output name if local-001 exists. The pinned requirements match the verified Colab numerical environment. Use a fresh environment and stop on installation errors rather than continuing with partial dependencies.

## Implementation and export fix

threat_platform/training.py verifies ingestion, splits by flow completion, audits overlap, fits models, selects validation thresholds and evaluates test. A staged output is published only after the saved XGBoost JSON reloads on CPU and matches every test score within absolute tolerance 1e-7, with identical alert decisions.

The metadata fix saves a finite allowlist of meaningful parameters. XGBoost's full parameter dictionary includes a NaN missing-value sentinel, which strict JSON rejects. Recording explicit parameters preserves strict JSON without writing nonstandard NaN values.

## Metrics and thresholds

Average precision weights precision by recall increments; trapezoidal PR-AUC integrates a curve differently. Both are reported separately. Precision is suspicious alerts divided by alerts; recall is detected suspicious events divided by suspicious events. False-positive rate (FPR) is false alerts divided by benign events.

Each threshold targets at most 1% empirical validation FPR using validation benign scores. With 99 benign validation rows, one false alert is already 1.01%, so the allowed count is zero. Ties are handled together. Zero observed false alerts does not prove a population guarantee. Freeze the threshold before testing and report the achieved test FPR; do not retune against test labels.

Validation recommended logistic regression. Test results: logistic had 6 false alerts among 382 benign events (1.57%) and 99.944% recall; XGBoost had 24 (6.28%) and 100% recall. Both missed the 1% test FPR target. See [verification](verification.md). High PR-AUC on selected, highly suspicious traffic does not establish readiness.

False alerts per day, service throughput and p95 latency are null. This short capture and offline training do not measure a full-day replay or prediction service. Later benchmarks must specify replay clock, benign traffic rate, hardware, batches, concurrency and timing.

## Bundle and CPU inference

| File | Purpose |
|---|---|
| model.json | Portable XGBoost model |
| metadata.json | Threshold, feature contract, device, versions and hashes |
| metrics.json | Model comparisons and promotion status |
| split-audit.json | Counts, chronology and overlaps |
| baseline-logistic.json | Scaler statistics and logistic parameters |
| features.py | Feature implementation snapshot |
| data-manifest.json | Ingestion provenance |
| README.md | Bundle instructions |

~~~python
from threat_platform.training import predict_bundle
rows = [{'duration_us': 1000000, 'packets': 12, 'bytes': 4096, 'protocol': 'TCP'}]
print(predict_bundle('artifacts/local-001', rows))
~~~

Results contain suspicious_score and alert using the saved threshold. Scores are not a probability-calibration guarantee. The loader checks feature version/order and model SHA-256 and uses CPU. The checksum detects changes against recorded metadata; it is not a creator signature. Use trusted bundles. No HTTP prediction service exists yet.

## Failures and advanced reasoning

Corrupted data hashes, duplicate IDs, missing classes, invalid measurements, unsupported feature versions and changed model hashes fail. Explicit GPU unavailability and existing output directories fail. A worse model's metrics remain visible and it stays not promoted.

Seeds and pinned versions improve repeatability, not bit-identical results across hardware. Record data/code/model hashes, versions and device. This is a development holdout already explored, with shared hosts, one short capture and excluded unknown labels. Reserve a new independent capture before final tuning.

## Exercises and next milestone

1. Compare dummy average precision to each partition's suspicious prevalence.
2. Explain why a validation-selected threshold gives different FPR on later traffic.
3. Train a separate CPU bundle and compare without overwriting the GPU run.
4. Modify a copy of model.json and verify checksum rejection.
5. Define promotion criteria including alert burden, independent evaluation and rollback.

Step 5 adds local experiment tracking and model versions. FastAPI, analyst workflow, monitoring and rollback are later milestones.

Primary references: [scikit-learn leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html), [average precision](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.average_precision_score.html), [XGBoost GPU](https://xgboost.readthedocs.io/en/stable/gpu/index.html), [model IO](https://xgboost.readthedocs.io/en/stable/tutorials/saving_model.html).
