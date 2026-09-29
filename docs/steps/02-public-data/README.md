# Step 2 — Public-data ingestion and provenance

## 1. Outcome and prerequisites

You now have a repeatable pipeline that downloads a particular public flow CSV, checks its identity, converts selected records into a documented event format, accounts for excluded rows, and publishes a complete run with a manifest. Everything uses Python's standard library.

Complete Step 1 first. You should understand JSONL, timestamps, labels, seeds, and file hashes. This step moves from invented fixtures to a real public research capture. The future workload is still **simulated replay**; it is not live production traffic.

The pipeline is:

```text
official flow CSV -> size + SHA-256 gate -> label selection + validation
                                             |
                         +-------------------+------------------+
                         |                                      |
                  accepted records                       exclusion reasons
                         |                                      |
                  duplicate check                         quarantine.jsonl
                         |
                  timestamp sort -> events.jsonl -> manifest.json
                                                          |
                                                 verify-ingestion
```

## 2. New concepts, from the basics

**Ingestion** means bringing external data into your system through a controlled process. Downloading a CSV is only the first part. You also need to know what the fields mean and what transformations were applied.

**Provenance** is the record of where an artifact came from: source URL, source hash, adapter version, configuration, runtime, code hashes, and output hashes. It lets a future reviewer reproduce or explain a result.

**Manifest** is a machine-readable inventory of a run. Here `manifest.json` records provenance and counts. It is more useful than a screenshot because another program can verify it.

**Quarantine** records the rows excluded from the accepted set and the reason for each exclusion. It does not mean all excluded rows are malformed. A valid record with an uncertain label is intentionally excluded too.

**Pinned source** means the project expects a specific file digest and byte count. If a server replaces the file, ingestion stops instead of silently evaluating a different dataset.

**Idempotent download** means rerunning the download command reuses an existing source only when its hash matches. A processed run is immutable by convention: ingestion refuses to overwrite an existing output directory.

**Atomic publication** means a completed artifact becomes visible in one filesystem operation. A staged run is renamed into place after successful processing. The downloader publishes a verified temporary file with a same-filesystem hard link, then removes its temporary name. This needs a filesystem supporting hard links, such as NTFS or typical Linux filesystems.

## 3. Why this dataset

CTU-13 provides labelled bidirectional network flows with capture timestamps. Scenario 11 is a manageable 14.6 MB download, allowing us to verify the entire ingestion path without a paid service or multi-gigabyte archive. Read the [official dataset description](https://www.stratosphereips.org/datasets-ctu13) and [scenario README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/README.md).

The source documentation distinguishes traffic originating from botnet hosts from traffic merely sent to those hosts. It also provides a CEST timeline. Those details determine the label and timestamp policy; they are not things to infer from column names alone.

This is one short historical capture, selected for an ingestion milestone. It is not sufficient evidence of general detection quality. Its attack traffic is concentrated in time, and the selected labelled set is heavily positive. Step 3 must inspect temporal class support before choosing any evaluation split. Additional captures may be necessary.

See [DATA_SOURCES.md](../../../DATA_SOURCES.md) for authors, paper, data license, exact file, checksum, and changes made by this project.

## 4. Run it

From the repository root, using Python 3.11 or newer:

```powershell
python -m unittest discover -s tests -v
python -m threat_platform download-ctu13
python -m threat_platform ingest-ctu13
python -m threat_platform verify-ingestion data/processed/ctu13-scenario11-v1
```

On Windows you can replace `python` with `py -3` or your interpreter's full path. No `pip install` is needed. The download is public and requires no login. Once cached, ingestion, verification, and tests work offline.

The default files are:

```text
data/
  raw/ctu13-scenario11.binetflow
  processed/ctu13-scenario11-v1/
    events.jsonl
    quarantine.jsonl
    manifest.json
```

Use a new output directory for a second run:

```powershell
python -m threat_platform ingest-ctu13 --output data/processed/repeat-run
python -m threat_platform verify-ingestion data/processed/repeat-run
```

The event and quarantine hashes should match the first run. Code/runtime changes may change the manifest even when event bytes remain identical. The manifest intentionally omits the current wall-clock time and absolute machine paths so equivalent runs are comparable.

### TLS certificates

If the host reports an untrusted issuer, update your trusted certificate store or supply a trusted PEM CA bundle:

```powershell
python -m threat_platform download-ctu13 --ca-file path/to/trusted-ca-bundle.pem
```

During development this host needed the [public CA bundle distributed by curl](https://curl.se/docs/caextract.html). It was used for the source download with certificate verification enabled. The bundle is an environment input and is not committed. Do not disable TLS verification to get past a certificate error. This option augments Python's default trust roots.

## 5. Mapping source columns to the v2 event contract

The source header must match the expected 15-column CSV header exactly. An unexpected header fails the entire run. This makes a source format change visible.

| Source or derived field | Output | Interpretation |
|---|---|---|
| `StartTime` | `timestamp` | UTC ISO-8601, preserving microseconds |
| `Dur` | `duration_us` | Decimal seconds converted exactly to integer microseconds |
| `TotPkts` | `packets` | Nonnegative integer |
| `TotBytes` | `bytes` | Nonnegative integer |
| `Proto` | `protocol` | TCP, UDP, or ICMP |
| `Label` | `label` | Selected normal = 0, selected botnet = 1 |
| Original `Label` | `source_label` | Audit metadata, never a model feature |
| CSV line number | `source_line` | Link back to the raw source |
| Canonical source fields | `event_id` | Dataset-prefixed SHA-256 fingerprint |
| Source/destination addresses | Host ID fields | Dataset-scoped deterministic hashes for future group audits |
| Adapter constants | Schema, dataset, source kind, simulation flag | Provenance, never model features |

Schema version 2 is separate from Step 1. The earlier fixture uses integer milliseconds and a smaller field set; this public adapter preserves microsecond resolution and adds audit metadata. Use `verify-ingestion` for these runs. The old `validate` command still validates only Step 1's fixture contract.

### Time conversion

The scenario documentation gives a CEST timeline. This adapter interprets its single capture date, August 18, 2011, as UTC+02:00 and rejects dates outside that scenario. For example, `15:40:00.123456` becomes `13:40:00.123456+00:00`. This documented fixed-date interpretation avoids requiring a timezone database on Windows. Do not reuse the fixed offset for different dates or datasets without revisiting their timezone evidence.

### Label selection

- `flow=From-Botnet-*`: positive label.
- `flow=From-Normal-*`: negative label.
- Every other label: excluded as `unlabelled_or_ambiguous`.

The policy is deliberately conservative, including excluding a `flow=Normal-*` variant that is not explicitly originating traffic. Background traffic does not become benign by default. This selection alters the class distribution; report the resulting prevalence rather than presenting it as ordinary network traffic.

## 6. Validation, duplicates, and exclusion accounting

After column-count validation and label selection, selected rows are checked for supported protocol, timestamp/date, finite nonnegative duration with microsecond precision, nonnegative integer counters, valid endpoint addresses, and source bytes not exceeding total bytes. Duration above one day is rejected by this scenario-specific contract. Unsupported protocols and uncertain labels are excluded with separate reasons.

Measurements of uncertain-label rows are not fully validated because those rows are excluded before conversion. Consequently, `invalid_rows: 0` means no conversion-invalid selected rows were found; it does **not** certify all raw rows as clean.

The flow fingerprint includes all stripped source fields except `Label`, with normalized time, duration, and counters. Repeated flows with the same binary label keep the first row and quarantine later copies. A repeated fingerprint with conflicting binary labels fails the entire run. Distinct flows that happen to share the small model feature set remain distinct.

SQLite stores accepted records and supports sorting without retaining every event payload in Python memory. The source is checked again after parsing to detect ordinary accidental changes during the run. On a fatal error, staging artifacts are removed and no completed run directory is published.

Every source row has one final disposition:

```text
source_rows = accepted_rows + excluded_rows
accepted_rows = benign_rows + suspicious_rows
excluded_rows = sum(exclusion_reasons)
```

`invalid_rows` is a subset of excluded rows. Do not add it again to the total.

## 7. Verified result

On the pinned source, the completed run produced:

| Measure | Result |
|---|---:|
| Source records | 107,251 |
| Accepted labelled records | 10,873 |
| Benign records | 2,709 |
| Suspicious records | 8,164 |
| Excluded uncertain-label records | 96,378 |
| Conversion-invalid selected records | 0 |
| Duplicate exclusions | 0 |
| Timestamp inversions among accepted input rows | 0 |

Accepted timestamps span `2011-08-18T13:39:35.096399+00:00` to `2011-08-18T13:55:39.897621+00:00`. This is about 16 minutes, not a full operational day.

The [example manifest](example-manifest.json) records exact hashes, sizes, rules, label counts, and runtime. The [verification record](verification.txt) describes tests and the repeated full-source run. These are ingestion results, not model accuracy or throughput measurements.

## 8. Code walkthrough

`threat_platform/ingestion.py` contains:

1. Source constants and `sha256_file`: the exact artifact identity and a streaming digest helper.
2. `download_source`: cache validation, verified HTTPS download, size ceiling, checksum gate, and publication of verified bytes.
3. `convert_row`: label policy, typed conversion, timezone interpretation, fingerprints, and provenance fields.
4. `ingest_source`: source verification, staged SQLite processing, quarantine, deterministic sort, manifest, and completed-run publication.
5. `verify_run`: output hash/size checks, accepted-event sanity checks, order/uniqueness checks, and manifest row accounting.

The CLI adds `download-ctu13`, `ingest-ctu13`, and `verify-ingestion`. Tests use tiny artificial CSV fixtures, mock only the network boundary, and patch the expected hash for those fixtures. Normal CLI execution always requires the pinned public source.

## 9. Advanced reasoning and limitations

**Integrity is not authenticity.** Hashes detect changes relative to recorded values. Someone able to replace both an artifact and its manifest can produce matching hashes. This project does not yet sign manifests. The original source pin was observed by this project, not supplied as a signed publisher assertion.

**Publication is not power-loss durability.** Staging prevents ordinary exceptions from exposing a completed partial run. There is no distributed lock, filesystem synchronization protocol, or crash-recovery service. Do not run concurrent writers to the same output path. Use distinct run directories.

**Leakage checks remain necessary.** Duplicate removal does not prevent the same host or session from appearing across time splits. Host IDs support later audits but must never be fed into a model accidentally. Label strings, line numbers, dataset identity, and time/capture-specific artifacts can also make results unrealistically easy.

**Pseudonyms remain linkable.** Deterministic hashes let us compare endpoints without storing raw IP addresses in normalized events. They are not a privacy guarantee, particularly for enumerable address spaces. Raw data stays local and ignored by Git.

**Validation is scoped.** This adapter interprets a pinned known source. It is not a general CSV upload endpoint and does not fully validate every unused field. `verify-ingestion` verifies a trusted run's integrity and accounting; it is not a cryptographic proof of provenance or a complete adversarial manifest validator.

**Evaluation must reflect the data.** The attack is concentrated late in the capture. A naive chronological split might have only one class in an early partition. Step 3 must show class counts by period and stop if the proposed split cannot support its metrics. A random split would hide the temporal problem instead of solving it.

**No daily false-alert extrapolation yet.** A short capture with a selected labelled subset cannot establish production false alerts per day. Later replay must state its clock, coverage, benign volume, and handling of unknown labels.

## 10. Troubleshooting and exercises

| Problem | What to do |
|---|---|
| Existing source checksum mismatch | Keep the file for investigation; use a fresh path to fetch the pinned source |
| Downloaded checksum mismatch | Stop and investigate source changes; do not change the expected hash just to bypass the gate |
| Output directory exists | Select a new `--output` run directory |
| Certificate issuer error | Update trust roots or pass a trusted `--ca-file` |
| No usable labelled events | Review source/label mapping; do not assume excluded traffic is benign |
| Output verification mismatch | Treat the run as modified and reproduce a new run from the verified source |

Exercises:

1. Run ingestion twice and compare event and quarantine digests.
2. Explain why 96,378 exclusions do not mean 96,378 broken records.
3. Modify a copied output file and confirm that verification fails.
4. Explain why `source_label` would leak the answer to a model.
5. Explain why high performance on this selected capture might not transfer to future traffic.

Next: Step 3, feature engineering and defensible chronological partitions, including temporal class coverage and host-overlap audits before any training.
