import unittest
from datetime import datetime, timedelta, timezone
import numpy as np
from threat_platform.features import encode, split_rows, audit_parts, threshold_at_fpr


def fixture():
    start = datetime(2020, 1, 1, tzinfo=timezone.utc)
    return [dict(event_id=str(i), timestamp=(start + timedelta(seconds=i)).isoformat(),
                 duration_us=0, packets=i + 1, bytes=100 + i, protocol="TCP",
                 label=i % 2, source_host_id="shared", destination_host_id=str(i))
            for i in range(20)]


class FeatureTests(unittest.TestCase):
    def test_metadata_cannot_change_features(self):
        a = fixture()[0]
        b = dict(a, label=1, source_label="attack", source_host_id="different",
                 timestamp="not used by encoder", event_id="other")
        np.testing.assert_array_equal(encode([a]), encode([b]))
        self.assertEqual(encode([]).shape, (0, 6))

    def test_invalid_measurements_fail(self):
        for field, value in [("bytes", -1), ("bytes", True), ("packets", 1.5),
                             ("duration_us", 86_400_000_001), ("protocol", "GRE")]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                encode([dict(fixture()[0], **{field: value})])

    def test_completion_time_not_start_time(self):
        rows = fixture()
        rows[0]["duration_us"] = 19_500_000
        parts = split_rows(rows)
        self.assertEqual(parts["test"][-1]["event_id"], "0")
        self.assertEqual(parts["train"][0]["event_id"], "1")

    def test_timestamp_ties_do_not_cross_boundary(self):
        rows = fixture()
        rows[11]["timestamp"] = rows[12]["timestamp"]
        parts = split_rows(rows)
        self.assertEqual(len(parts["train"]), 11)
        self.assertEqual(parts["validation"][0]["event_id"], "11")

    def test_duplicate_ids_fail_even_across_partitions(self):
        rows = fixture()
        rows[-1]["event_id"] = rows[0]["event_id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            split_rows(rows)

    def test_class_support_and_utc_required(self):
        rows = fixture()
        for row in rows[16:]:
            row["label"] = 1
        with self.assertRaisesRegex(ValueError, "test needs both"):
            split_rows(rows)
        rows = fixture()
        rows[0]["timestamp"] = "2020-01-01T00:00:00"
        with self.assertRaisesRegex(ValueError, "UTC"):
            split_rows(rows)

    def test_host_overlap_reported(self):
        audit = audit_parts(split_rows(fixture()))
        self.assertEqual(audit["overlap"]["train/test"]["host_ids"], 1)
        self.assertEqual(audit["overlap"]["train/test"]["event_ids"], 0)

    def test_threshold_ties_and_float32_rounding(self):
        scores = np.asarray([.5, .5, .9], dtype=np.float32)
        threshold = threshold_at_fpr([0, 0, 1], scores, .01)
        self.assertGreater(threshold, .5)
        self.assertEqual((scores.astype(np.float64) >= threshold).tolist(), [False, False, True])
        scores = np.asarray([.9, .8, .8, .1], dtype=np.float32)
        threshold = threshold_at_fpr([0, 0, 0, 0], scores, .5)
        self.assertEqual(int((scores.astype(np.float64) >= threshold).sum()), 1)

    def test_threshold_rejects_missing_negatives_or_nonfinite(self):
        for labels, scores, fpr in [([1], [.5], .01), ([0], [np.nan], .01),
                                    ([0], [.5], 1), ([0, 1], [.5], .01)]:
            with self.assertRaises(ValueError):
                threshold_at_fpr(labels, scores, fpr)
