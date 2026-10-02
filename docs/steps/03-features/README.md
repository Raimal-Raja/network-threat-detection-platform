# Step 3 — Features and chronological evaluation

## Outcome and basic concepts

This step converts verified public network flows into six features and chronological partitions. Finish [Step 2](../02-public-data/README.md) first. Python 3.11+ and requirements-training.txt are sufficient; CPU execution is free.

A row represents a flow. Features are measurements available at prediction time; labels are known outcomes (0 benign, 1 suspicious). Training fits parameters, validation selects models and thresholds, and test measures later traffic. Leakage occurs when fitting or selection receives information unavailable at prediction time.

## Feature contract

Version: completed-flow-v1. The float32 matrix has exactly this order:

| Position | Feature | Meaning |
|---|---|---|
| 0 | log1p_duration_us | Natural log of 1 plus duration in microseconds |
| 1 | log1p_packets | Natural log of 1 plus packet count |
| 2 | log1p_bytes | Natural log of 1 plus byte count |
| 3 | is_tcp | TCP indicator |
| 4 | is_udp | UDP indicator |
| 5 | is_icmp | ICMP indicator |

Log1p accepts zero and compresses large values. Protocol indicators avoid inventing a numeric category order. Labels, timestamps, event IDs, hosts and provenance are excluded from inputs. Numeric fields require genuine nonnegative integers within signed 64-bit range; booleans fail. Duration is capped at one day and unsupported protocols fail.

## Chronology and availability

Complete duration, packet counts and byte counts exist only after a flow ends. The clock is UTC start plus duration, so this is completed-flow detection. Sorting only by start time could allow a long unfinished training flow to cross a validation boundary.

split_rows sorts by completion time and event ID, with 60/20/20 row targets. Timestamp ties move together into the later partition. Actual percentages may change. Duplicate IDs, invalid binary labels, non-UTC timestamps and partitions missing a class fail rather than silently forcing a random split.

## Run and inspect on D drive

From D:\GitHub\network-threat-detection-platform:

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-training.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
~~~

threat_platform/features.py contains encode, completion_time, split_rows, audit_parts and threshold_at_fpr. After Step 2 ingestion:

~~~python
import json
from pathlib import Path
from threat_platform.ingestion import verify_run
from threat_platform.features import encode, split_rows, audit_parts
run = Path('data/processed/ctu13-scenario11-v1')
verify_run(run)
rows = [json.loads(line) for line in (run / 'events.jsonl').read_text().splitlines()]
parts = split_rows(rows)
print(encode(parts['train']).shape)
print(json.dumps(audit_parts(parts), indent=2))
~~~

Step 4 training automatically saves split-audit.json. Keep data and artifacts in their ignored D-drive directories.

## Interpret the audit

Each partition records row/class counts, completion boundaries and a hash of ordered IDs. Pairwise overlaps count event IDs, hosts and distinct feature vectors. Duplicate IDs are rejected. Shared hosts rule out claims of independent-host evaluation. Repeated feature vectors may be legitimate identical measurements rather than duplicated source events; report them rather than silently deleting them.

The verified run has 6,523 training rows (2,228 benign), 2,175 validation rows (99 benign), and 2,175 test rows (382 benign). Unknown/background labels were excluded in ingestion. This high suspicious prevalence is not representative production traffic. StandardScaler learns only from training rows in the Step 4 logistic pipeline; encode itself learns no statistics.

## Failure tests and advanced limits

Tests cover invalid measurements, feature allowlisting, completion ordering, timestamp ties, duplicate IDs, missing classes, UTC, overlaps and threshold ties. Scores use float64 when compared against a nextafter cutoff, avoiding accidental float32 rounding back onto a tie.

Chronology alone does not remove shared-host dependence, repeated patterns or capture artifacts. This short, single capture cannot establish performance on new days/networks. The test period was already inspected during development and is a development holdout. A final study needs a new independent capture, frozen decisions and a label-availability policy.

## Exercises

1. Compare start-time and completion-time ordering for two flows with different durations.
2. Put several rows exactly at a split boundary; explain the partition sizes.
3. Explain the difference between host overlap, feature overlap and duplicate event IDs.
4. Design independent-host/day evaluation without tuning against its labels.

Continue to [Step 4 — training and saved models](../04-training/README.md).
