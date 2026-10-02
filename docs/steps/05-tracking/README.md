# Step 5 — Local experiment tracking and model versions

## Outcome and prerequisites

This milestone records Step 4 model bundles in a free local SQLite ledger. Every registered version has a copied bundle, SHA-256 checksums, creation time, a note, training settings, package versions, data/code hashes, metrics and split audit. No cloud account, API key, database server or numerical package installation is needed to register a bundle. Python 3.11+ is sufficient.

Complete [Step 4](../04-training/README.md) and download/unzip its model bundle first. Do not retrain just to use tracking. Registration copies the eight bundle files; it does not upload model weights to GitHub or claim the model is deployable.

## Basic concepts

An experiment compares a method or configuration. A training run is one execution of that method. A model artifact contains the learned parameters. A version identifies an archived bundle so a later prediction service can refer to exactly what it loaded.

A model hash alone misses changes to the alert threshold or preprocessing. This registry fingerprints all eight files, including metadata and metrics. Importing identical bytes twice returns the same version. Changing a threshold, report, package metadata or training timestamp creates another bundle fingerprint and version.

Version numbers are local to one store, start at 1 and follow insertion order. They are not universal model identities or rankings. Use bundle_sha256 for content identity across stores.

## Why SQLite in this milestone

Python includes SQLite, so this first tracking implementation has no additional dependencies. The proposed stack included MLflow; MLflow is not implemented here. A later adapter can mirror the same records into self-hosted MLflow if its UI or integrations become useful. Keep this simple offline path as a free fallback.

The storage layout is:

~~~text
artifacts/tracking/
  experiments.sqlite3
  bundles/
    <bundle_sha256>/
      model.json
      metadata.json
      metrics.json
      split-audit.json
      baseline-logistic.json
      features.py
      data-manifest.json
      README.md
~~~

artifacts/ is ignored by Git. The ledger stores the complete metadata, metrics and file hashes in report_json. Its record retains the original registration note and time. The registry copies bundles so deleting or changing the original download does not destroy the archived version.

## Step-by-step use on D drive

First update your repository:

~~~powershell
Set-Location D:\GitHub\network-threat-detection-platform
git pull --ff-only origin main
~~~

Unzip your Colab download. The notebook ZIP puts bundle files inside a model folder. For example, if you extract into artifacts/colab-download, the bundle path is artifacts/colab-download/model. Confirm that directory contains the eight files listed above. Substitute your actual extraction path below.

~~~powershell
python -m threat_platform.tracking register --bundle artifacts/colab-download/model --note "T4 completed-flow research run"
python -m threat_platform.tracking list
python -m threat_platform.tracking show 1
~~~

The output is JSON. Inspect version, bundle_sha256, status, report.metadata and report.metrics. These commands need no training dependencies. If you use the project virtual environment, replace python with .\.venv\Scripts\python.exe.

For a bundle trained locally:

~~~powershell
python -m threat_platform.tracking register --bundle artifacts/local-001 --note "CPU comparison"
~~~

To choose another store, put the global option before the command:

~~~powershell
python -m threat_platform.tracking --store artifacts/alternative-tracking register --bundle artifacts/local-001
python -m threat_platform.tracking --store artifacts/alternative-tracking show 1
~~~

To save an inspection report outside the ledger:

~~~powershell
python -m threat_platform.tracking show 1 | Out-File -Encoding utf8 artifacts/version-1-report.json
~~~

Reading records verifies the stored bundle again. Unknown versions and corrupted records fail with a nonzero exit code. There is no production alias, deployment command or automatic promotion.

## Implementation walkthrough

threat_platform/tracking.py implements:

1. inspect_bundle: requires exactly the eight Step 4 regular files, rejects symbolic links, parses JSON, checks artifact version, simulation/research flags, saved-model reload evidence and model hash.
2. digest: hashes files in chunks rather than loading large models into memory.
3. register: copies to a staging directory, rechecks the complete report to catch changes during copying, then begins a SQLite write transaction.
4. Duplicate handling: an existing fingerprint returns its verified original record; a new fingerprint receives a new version.
5. Snapshot publication: a verified folder is renamed into its content-addressed location, then the database record is committed.
6. show and versions: recompute the snapshot report and compare it against the ledger before returning results.

The registry preserves training comparisons for dummy, logistic and XGBoost. It does not recompute their numerical predictions or independently certify their metric truth. It trusts that the bundle came from your verified Step 4 run; the fixture tests exercise the registry contract, not model quality.

## Compare versions responsibly

Use show for each version and compare:

| Field | Question |
|---|---|
| events_sha256 | Were the same event bytes used? |
| feature_version / feature_names | Was the input contract the same? |
| code_sha256 | Did training or preprocessing code change? |
| model_parameters / packages | Did configuration or dependencies change? |
| actual_training_device | Was GPU or CPU used? |
| metrics.audit | Were partitions and temporal boundaries comparable? |
| validation metrics | What evidence supported model/threshold selection? |
| test metrics and limitations | What happened on the development holdout? |

Matching source data alone does not guarantee matching split policy or evaluation protocol. Compare the audit too. Preserve worse versions to understand regressions. Do not tune repeatedly on test results and then call the same period an untouched benchmark.

The Step 4 XGBoost run had 24 false alerts among 382 benign test events, exceeding its target. Registration leaves production_ready=false and status=research_candidate. A registry version is an inventory item, not security approval.

## Failures, concurrency and crash recovery

Missing or extra files, symlinks, malformed/nonfinite JSON, a model checksum mismatch, missing reload evidence, unsupported artifact versions and claimed production readiness are rejected. All tracked files are hashed, so metadata-only tampering is detected on read.

A SQLite BEGIN IMMEDIATE transaction serializes registration writers; the connection waits up to 30 seconds for locks. The concurrent duplicate-import test confirms two simultaneous registrations produce one version. This is a local filesystem design, not a distributed registry or a network-share deployment recommendation.

If a process crashes after publishing its snapshot but before committing the database row, that directory can remain orphaned. Reimporting the original bundle verifies it and completes registration. Staging directories from a hard crash may also remain. Failed ledger writes do not approve or serve a model.

Checksums detect changes against a trusted record; they are not signatures. Someone able to edit both the database and artifacts can forge a record. Use local file permissions and backups, and add signing/access control before multiuser deployment.

## Verification and tests

See [verification](verification.md). Six new lifecycle/integrity tests and 27 existing standard-library tests passed. Numerical feature/training tests were not rerun in this environment; the prior Step 4 run passed all 38 existing tests.

Run just the new tests without installing numerical packages:

~~~powershell
python -m unittest discover -s tests -p test_tracking.py -v
~~~

After installing requirements-training.txt, run the complete repository suite:

~~~powershell
python -m unittest discover -s tests -v
~~~

The full repository now contains 44 tests. That count is not a claim that all 44 were rerun for this milestone.

## Backup and advanced limitations

Stop registration commands before copying the entire artifacts/tracking directory to a backup location. Preserve both the database and bundles. A database-only backup loses model files; bundle-only backups lose version notes and ordering. For a future always-running service, use SQLite's backup API instead of copying a live database file.

The snapshot stores completed-flow measurements and development evaluation evidence. It does not provide drift detection, artifact signatures, semantic model loading checks, a browser UI, remote access, MLflow integration, deployment aliases or rollback execution. Those are separate later milestones.

## Exercises

1. Register the same bundle twice and confirm the version remains unchanged.
2. Change a copied metadata threshold; register it and explain the new fingerprint.
3. Delete your original download after ensuring its snapshot verifies; inspect the registered version.
4. Modify a copied store's metadata and confirm show rejects it.
5. Design a future promotion gate requiring independent evaluation and an alert budget.

Next: Step 6, individual/batch FastAPI inference using a verified research model version.

References: [Python sqlite3](https://docs.python.org/3/library/sqlite3.html), [SQLite transactions](https://www.sqlite.org/lang_transaction.html), [Python hashlib](https://docs.python.org/3/library/hashlib.html).
