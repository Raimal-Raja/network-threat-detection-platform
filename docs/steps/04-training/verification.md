# GPU training verification — 2026-10-02

Observed in the user's Colab runtime: Tesla T4, actual XGBoost device cuda:0, Python 3.13, NumPy 2.1.3, SciPy 1.16.3, scikit-learn 1.6.1, XGBoost 3.4.1. All 38 tests passed in 0.783 seconds after the strict-JSON metadata fix now included in training.py.

The run used d5de40d1b93dbf37a9c67ea55791345ac5dd7bfe plus that fix. It invoked threat_platform.training with --device cuda --target-fpr 0.01 and saved artifacts/colab-gpu-001 under the Colab project. This does not assert that artifacts were copied to D drive.

## Data

CTU-13 scenario 11: 107,251 source rows; 10,873 accepted (2,709 benign, 8,164 suspicious); 96,378 unknown/background excluded. No duplicate accepted IDs.

Source SHA-256: cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c

Events SHA-256: e3f8f97500ec8024405c1af3ac2cfeb031d07561ccced3fb64cf392f5e35f2ad

| Partition | Rows | Benign | Suspicious |
|---|---:|---:|---:|
| Train | 6523 | 2228 | 4295 |
| Validation | 2175 | 99 | 2076 |
| Test | 2175 | 382 | 1793 |

## Test at validation-selected thresholds

| Model | Average precision | Trapezoidal PR-AUC | Recall | False alerts / benign | FPR |
|---|---:|---:|---:|---:|---:|
| Dummy | 0.8243678161 | 0.9121839080 | 0% | 0 / 382 | 0% |
| Logistic | 0.9999959708 | 0.9999959697 | 99.9442% | 6 / 382 | 1.5707% |
| XGBoost GPU | 0.9999907457 | 0.9999928927 | 100% | 24 / 382 | 6.2827% |

Thresholds: dummy 0.6584393683887783; logistic 0.05064665738048085; XGBoost 0.018279122188687328. Validation FPR was zero for each model. Learned-model validation recall was 100%; dummy recall was zero. One false alert among 99 validation benign rows would already exceed 1%.

Validation recommended logistic regression. The exported XGBoost JSON reloaded on CPU and matched all test scores within absolute tolerance 1e-7 and identical alert decisions. Both learned models missed the 1% test FPR target. production_ready=false; promotion_decision=not_promoted_research_demo.

## Limitations

SIMULATED, within-capture evaluation with shared hosts, selected labels and a development holdout already inspected. It is not an untouched independent benchmark. High suspicious prevalence differs from ordinary traffic. False alerts per day, throughput and p95 latency are null because full-day replay and the prediction service were not measured. Fit time is not prediction latency.
