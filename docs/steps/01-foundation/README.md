# Step 1 — Foundation, event contract, and validation

## 1. What you build and why

This step creates a repeatable source of small, labelled network-event fixtures and a validator that refuses malformed data. Before a model can learn useful patterns, the system needs a shared definition of an event. Without that definition, one program might interpret seconds as milliseconds, treat a missing measurement as zero, or silently accept a text value where a number is expected.

The flow implemented here is:

```text
count + seed -> synthetic generator -> JSONL file -> validator -> JSON report
                                                       |
                                                       +-> failure with line number
```

This is a software foundation, not a trained detector. No packets are captured and no attacks are performed. Everything generated here is synthetic and marked `simulated: true`.

By the end, you should be able to run a Python module, explain the event fields, reproduce a dataset, diagnose a validation failure, and distinguish basic duplicate checks from a complete leakage audit.

## 2. Basic concepts

**Network event:** a record describing an observed communication or summary of communication. Our fixture resembles a small flow summary. A real public dataset will require a documented adapter; these fields are not a universal standard.

**Feature:** an input available to a model at prediction time. Duration, packet count, byte count, and protocol are candidate inputs. A later phase will define the feature allowlist explicitly.

**Label:** the answer used for training or evaluation. Here `0` means benign and `1` means suspicious. A label must never become an input feature. Real inference requests will not require a label; this contract is only for labelled offline data.

**Schema or contract:** the fields and rules all participating components agree to use. This step treats missing and unexpected fields as errors instead of guessing what they mean.

**JSONL:** JSON Lines, with one JSON object per line. It is convenient for inspecting and processing records incrementally. A JSONL file is not a single JSON array.

**Seed:** an integer that initializes a pseudorandom generator. Repeating the seed, count, code, and compatible Python runtime repeats the fixture. Random-looking data can still be deterministic.

**UTC:** a common reference timezone. Requiring explicit UTC avoids ambiguous local timestamps, especially around daylight-saving changes. Source timestamps must later be converted using documented source timezone information.

**SHA-256:** a digest of file bytes. Matching digests help identify an unchanged artifact. A digest does not prove that labels are correct or that a dataset is unbiased.

## 3. Setup and commands

Open a terminal in `outputs/network-threat-detection-platform`. If you already have Python 3.11+, use `python` below. No packages need installing.

```powershell
python --version
python -m unittest discover -s tests -v
python -m threat_platform generate --output data/demo.jsonl --count 1000 --seed 42
python -m threat_platform validate data/demo.jsonl
```

On Windows, if Python is installed but `python` is not on PATH, try the Python launcher:

```powershell
py -3 --version
py -3 -m unittest discover -s tests -v
py -3 -m threat_platform generate --output data/demo.jsonl --count 1000 --seed 42
py -3 -m threat_platform validate data/demo.jsonl
```

If neither command is available, install Python from [python.org](https://www.python.org/downloads/) and reopen the terminal, or run your interpreter by its full path. A virtual environment is useful when third-party packages arrive; it is unnecessary for the standard-library-only milestone.

`-m threat_platform` asks Python to execute the package's `__main__.py`. Run it from the repository root so Python can locate that package. `--count` controls the number of records and `--seed` controls the deterministic fixture.

Successful commands return exit code `0` and a JSON report. Bad input or an inaccessible file returns exit code `2` and an error on stderr. Use `$LASTEXITCODE` immediately after a command in PowerShell to inspect its exit code.

## 4. Event contract, version 1

| Field | Type and meaning | Rule |
|---|---|---|
| `event_id` | String identifier | Nonempty after whitespace trimming; unique in the file |
| `timestamp` | ISO-8601 timestamp | Explicit UTC, such as `2026-01-01T00:00:00+00:00` |
| `duration_ms` | Integer duration in milliseconds | Zero or positive |
| `packets` | Integer packet count | Zero or positive |
| `bytes` | Integer byte count | Zero or positive |
| `protocol` | String protocol name | Exactly `TCP`, `UDP`, or `ICMP` |
| `label` | Integer ground truth | Exactly `0` or `1` |
| `simulated` | Boolean provenance marker | Exactly `true` |

Example of a structurally valid record:

```json
{"event_id":"example-1","timestamp":"2026-01-01T00:00:00+00:00","duration_ms":200,"packets":8,"bytes":4096,"protocol":"TCP","label":0,"simulated":true}
```

The validator rejects booleans in numeric fields. Python treats `bool` as a subclass of `int`, so `isinstance(True, int)` would accept a value we do not want. The implementation uses `type(value) is int` for this offline contract.

No upper bounds on measurements or cross-field physics are asserted yet: we have not selected a real source or established its units and semantics. This validator checks structural correctness, not whether every accepted record could occur on a real network. Generation count is limited to one million to avoid accidentally requesting an enormous fixture.

## 5. Code walkthrough

`threat_platform/events.py` contains the data logic:

1. `validate_event` checks exact fields, types, ranges, protocol, simulation marker, and timezone. It returns a parsed timestamp for ordering and canonicalization.
2. `generate_events` uses a private `random.Random(seed)` instance so unrelated random calls cannot disturb it. It emits one record per simulated minute starting January 1, 2026 UTC.
3. `_unique_keys` rejects repeated keys in a JSON object. Otherwise many parsers silently keep the last value, hiding ambiguous input.
4. `_reject_constant` rejects nonstandard JSON constants such as `NaN` and `Infinity`.
5. `inspect_dataset` reads lines, hashes original bytes, validates records, checks duplicates and ordering, then returns a summary. It never rewrites the input.
6. `write_dataset` writes deterministic UTF-8 JSONL using sorted keys and LF line endings. Exclusive file creation refuses to overwrite an existing path, then the newly written dataset is validated.

`threat_platform/__main__.py` handles the command-line interface and readable error output. Generation adds the seed, generator version, and Python version to its report. Validation alone cannot recover the seed from arbitrary file bytes and does not pretend to do so.

`tests/test_events.py` exercises deterministic output, valid summaries, invalid fields, duplicate identifiers, copied records, timestamp ordering, malformed JSON, duplicate JSON keys, invalid UTF-8, overwrite protection, bad counts, and command-line exit codes.

`.gitignore` keeps generated datasets, caches, environments, and local secrets out of ordinary Git tracking. The directory is a source project; a remote repository has not been created or published.

## 6. Read the result

The JSON report includes `rows`, `suspicious_rows`, `benign_rows`, first and last timestamps, `schema_version`, `sha256`, and `simulated`. Counts should sum correctly. For 1,000 generated events spaced one minute apart, the timestamps span 999 minutes. This span is an artificial fixture clock, not a measured traffic rate.

The generator chooses a suspicious label with probability 0.08. This does not guarantee exactly 80 positives in 1,000 rows. Positive events draw packet counts from 1–150; benign events draw from 1–100. The distributions overlap, but this intentionally invented signal makes the fixture unsuitable for real detection performance claims. Protocol and other values are also artificial.

The saved `verification.txt` and `example-generation-report.json` in this directory document the actual checks and generated example. Do not substitute these fixture counts for evaluation metrics.

To verify reproducibility yourself, generate a second filename with the same count and seed, then compare the two `sha256` fields. Changing the seed should change the digest. Changing whitespace or line endings also changes the byte digest, even if the parsed records mean the same thing.

## 7. Failure cases and troubleshooting

| Symptom | Explanation and action |
|---|---|
| `python` is not recognized | Use the full interpreter path above or configure a standalone Python installation |
| `No module named threat_platform` | Change into the repository root before running the command |
| File already exists | Choose a new output filename; generation deliberately protects existing files |
| Error naming a line | Inspect that line in an editor; fix the source or create a separate corrected copy |
| Duplicate event ID | The same identifier occurs more than once, even if measurements differ |
| Duplicate content | Measurements, protocol, simulation marker, and canonical timestamp match another record despite a different ID or label |
| Timestamp-order error | An event is earlier than the previous event; investigate the source ordering |
| Disk-full error | Free space before retrying; an interrupted write may leave a partial file, so use a fresh output path |

Try changing `packets` to `-1` in a copy of the generated file. Validation should fail with a line number. Try reversing two records: chronological validation should fail. The tests perform equivalent failure checks automatically.

No invalid rows are silently discarded. Fail-fast behavior is intentionally simple for this first milestone. Public ingestion will add explicit quarantine counts and reasons so downstream users can see what was excluded.

## 8. Advanced design details and limits

**Identity and content are different.** Identifier uniqueness catches repeated IDs. Content matching excludes ID and label, so copying a row with a new ID or changed label does not evade the duplicate check. Timestamp spellings such as `Z` and `+00:00` are normalized before matching. Identical measurements at different times are allowed because recurring traffic can be legitimate.

**These checks do not eliminate leakage.** Repeated flows at shifted timestamps, related sessions across split boundaries, source-specific artifacts, and label-derived columns need additional checks. Later phases must split chronologically, audit entity overlap, exclude label/identifier/provenance fields from features, and fit preprocessing only on training data. A sorted file alone is insufficient.

**Streaming has a memory caveat.** File parsing is line by line, but identifier and content sets grow with the number of records. Validation uses O(n) auxiliary memory, with content strings increasing memory with row size. Large datasets need a database-backed or external-sort duplicate strategy. This CLI also has no hostile-input line-length limit; do not expose it as a network service.

**Reproducibility needs more than a seed.** Preserve code, configuration, Python/dependency versions, source provenance, and data hashes. This milestone produces seed/runtime metadata but does not yet implement a complete immutable run manifest. Step 2 adds that manifest. Avoid claiming identical generated bytes across all future Python implementations or versions.

**File writes are not yet transactional.** Exclusive creation protects an existing file but cannot prevent a partial new file after a crash or full disk. Generation reports success only after validation. Future ingestion should stage, validate, and atomically publish artifacts with their manifests. Do not treat the mere existence of a file as a success signal.

**Labels and inference have different contracts.** Keeping labels in an offline dataset is correct; requiring them in a prediction API would be a design mistake. The service phase will define an unlabelled inference schema and a shared feature transformation.

**Validation is not threat detection.** These checks demonstrate software behavior under malformed inputs and duplicates. Model metrics, latency, drift, monitoring, and rollback are deliberately not claimed at this milestone.

## 9. Exercises and completion checklist

1. Generate 100 records with seed 7 and repeat into a different file. Compare hashes.
2. Change only the seed and explain why the output changes.
3. Make a copied dataset invalid in three different ways and read each error.
4. Explain why the label, event ID, and simulation flag must not become model features.
5. Explain why one event per simulated minute does not establish real-world false alerts per day.

Step 1 is complete when the test suite passes, generation and standalone validation agree on the file hash, and you can explain the current limitations. The next step will ingest a public dataset with documented terms, source units, timezone decisions, checksums, and a reproducible provenance manifest. No public dataset has been downloaded in Step 1.
