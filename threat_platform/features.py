"""Six allowlisted features and chronological, completed-flow evaluation."""
import bisect
import hashlib
import json
from datetime import datetime, timedelta
from itertools import combinations

import numpy as np

FEATURE_VERSION = "completed-flow-v1"
FEATURE_NAMES = ["log1p_duration_us", "log1p_packets", "log1p_bytes",
                 "is_tcp", "is_udp", "is_icmp"]
NUMERIC_FIELDS = ("duration_us", "packets", "bytes")


def encode(rows):
    """Validate measurements and ignore labels, hosts, IDs and provenance."""
    vectors = []
    for row in rows:
        for key in NUMERIC_FIELDS:
            value = row[key]
            if type(value) is not int or not 0 <= value <= 2**63 - 1:
                raise ValueError(f"{key} must be a nonnegative 64-bit integer")
        if row["duration_us"] > 86_400_000_000:
            raise ValueError("duration exceeds the one-day event contract")
        if row["protocol"] not in ("TCP", "UDP", "ICMP"):
            raise ValueError("unsupported protocol")
        vectors.append([*(np.log1p(row[key]) for key in NUMERIC_FIELDS),
                        *(float(row["protocol"] == p) for p in ("TCP", "UDP", "ICMP"))])
    return np.asarray(vectors, dtype=np.float32).reshape((-1, len(FEATURE_NAMES)))


def completion_time(row):
    timestamp = datetime.fromisoformat(row["timestamp"])
    if timestamp.tzinfo is None or timestamp.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC")
    duration = row["duration_us"]
    if type(duration) is not int or not 0 <= duration <= 86_400_000_000:
        raise ValueError("invalid duration")
    return timestamp + timedelta(microseconds=duration)


def split_rows(rows):
    """Fixed 60/20/20 row targets; entire timestamp ties go to the later set."""
    rows = sorted(rows, key=lambda r: (completion_time(r), r["event_id"]))
    if len(rows) < 5:
        raise ValueError("not enough rows")
    ids = [r["event_id"] for r in rows]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate event IDs; refusing evaluation")
    if any(type(r["label"]) is not int or r["label"] not in (0, 1) for r in rows):
        raise ValueError("binary integer labels required")
    times = [completion_time(r) for r in rows]
    a = bisect.bisect_left(times, times[int(len(rows) * .6)])
    b = bisect.bisect_left(times, times[int(len(rows) * .8)])
    parts = dict(train=rows[:a], validation=rows[a:b], test=rows[b:])
    for name, part in parts.items():
        if {r["label"] for r in part} != {0, 1}:
            raise ValueError(f"{name} needs both classes; obtain more data")
    return parts


def audit_parts(parts):
    report = {"clock": "flow completion = UTC start + full duration",
              "split_policy": "fixed 60/20/20 row targets, ties kept together",
              "feature_version": FEATURE_VERSION, "features": FEATURE_NAMES,
              "partitions": {}, "overlap": {}}
    ids, hosts, vectors = {}, {}, {}
    for name, rows in parts.items():
        matrix = encode(rows)
        ids[name] = {r["event_id"] for r in rows}
        hosts[name] = {r[k] for r in rows for k in ("source_host_id", "destination_host_id")}
        vectors[name] = {tuple(v) for v in matrix.tolist()}
        times = [completion_time(r) for r in rows]
        report["partitions"][name] = {
            "rows": len(rows), "benign": sum(r["label"] == 0 for r in rows),
            "suspicious": sum(r["label"] == 1 for r in rows),
            "first_completion_utc": min(times).isoformat(),
            "last_completion_utc": max(times).isoformat(),
            "event_id_order_sha256": hashlib.sha256(
                ("\n".join(r["event_id"] for r in rows) + "\n").encode()).hexdigest()}
    for left, right in combinations(parts, 2):
        report["overlap"][f"{left}/{right}"] = {
            "event_ids": len(ids[left] & ids[right]),
            "host_ids": len(hosts[left] & hosts[right]),
            "distinct_feature_vectors": len(vectors[left] & vectors[right])}
    report["limitations"] = [
        "SIMULATED within-capture demonstration; not independent-host/day validation.",
        "Host and feature-vector overlap is reported, not silently removed.",
        "Features exist only when the flow is complete, not when it starts.",
        "Test period was already inspected in the exploratory notebook; it is a development holdout.",
        "Background/unknown labels are excluded; selected traffic is not production prevalence."]
    return report


def threshold_at_fpr(labels, scores, target=.01):
    """Highest-recall cutoff satisfying the empirical negative budget, with ties."""
    labels = np.asarray(labels)
    scores = np.asarray(scores, dtype=np.float64)
    if labels.ndim != 1 or scores.shape != labels.shape or len(labels) == 0:
        raise ValueError("one score per label required")
    if not np.isfinite(scores).all() or not np.isin(labels, [0, 1]).all():
        raise ValueError("finite scores and binary labels required")
    if not 0 <= target < 1:
        raise ValueError("target FPR must be in [0, 1)")
    negative = np.sort(scores[labels == 0])[::-1]
    if not len(negative):
        raise ValueError("validation needs benign examples")
    allowed = int(target * len(negative))
    return float(np.nextafter(negative[allowed], np.inf))
