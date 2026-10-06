"""Persistence, retry and review-conflict tests with standard-library fixtures."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threat_platform.cases import CaseStore, Conflict, MissingCase


class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cases.sqlite3"
        self.store = CaseStore(self.path)
        self.flow = {"duration_us": 1000, "packets": 2, "bytes": 100, "protocol": "TCP"}
        self.prediction = {"bundle_sha256": "fixture", "model_version": 1,
                           "alert": True, "suspicious_score": .8, "threshold": .5,
                           "simulated": True, "production_ready": False}
        self.explanation = {"fixture": True}

    def create(self):
        return self.store.save("event-1", self.flow, self.prediction, self.explanation)

    def test_retry_is_idempotent_and_changed_input_conflicts(self):
        first = self.create()
        self.assertEqual(self.create()["id"], first["id"])
        with self.assertRaises(Conflict):
            self.store.save("event-1", {**self.flow, "bytes": 101}, self.prediction, self.explanation)
        self.assertEqual(self.store.list()["total"], 1)

    def test_snapshot_and_history_survive_reopening(self):
        case = self.create()
        self.store.feedback(case["id"], 0, "analyst", "benign", "Likely false alert")
        restored = CaseStore(self.path).get(case["id"])
        self.assertEqual(restored["prediction"], self.prediction)
        self.assertEqual(restored["review"], "benign")
        self.assertEqual(restored["revision"], 1)
        self.assertEqual(restored["feedback"][0]["note"], "Likely false alert")

    def test_stale_review_does_not_overwrite_history(self):
        case = self.create()
        self.store.feedback(case["id"], 0, "first", "uncertain", "Investigate")
        with self.assertRaises(Conflict):
            self.store.feedback(case["id"], 0, "second", "suspicious", "Stale")
        result = self.store.feedback(case["id"], 1, "second", "suspicious", "Updated")
        self.assertEqual([r["revision"] for r in result["feedback"]], [1, 2])
        self.assertEqual(result["prediction"], self.prediction)

    def test_filters_pagination_and_missing_case(self):
        case = self.create()
        self.store.feedback(case["id"], 0, "local", "benign", "")
        self.assertEqual(self.store.list(alert_only=True, review="benign")["total"], 1)
        self.assertEqual(self.store.list(review="unreviewed")["total"], 0)
        self.assertEqual(self.store.list(limit=1, offset=1)["cases"], [])
        with self.assertRaises(MissingCase):
            self.store.get("unknown")
        with self.assertRaises(ValueError):
            self.store.list(limit=0)

    def test_notes_are_literal_and_large_counts_display_exactly(self):
        self.flow["bytes"] = 2**63 - 1
        case = self.create()
        note = "<script>alert(1)</script>'; DROP TABLE cases;--"
        result = self.store.feedback(case["id"], 0, "local", "uncertain", note)
        self.assertEqual(result["feedback"][0]["note"], note)
        self.assertEqual(result["flow_display"]["bytes"], str(2**63 - 1))
        self.assertEqual(self.store.list()["total"], 1)

    def test_concurrent_reviews_have_one_winner(self):
        case = self.create()
        def review(name):
            try:
                self.store.feedback(case["id"], 0, name, "uncertain", "")
                return "saved"
            except Conflict:
                return "conflict"
        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(review, ["one", "two"]))
        self.assertCountEqual(result, ["saved", "conflict"])
        self.assertEqual(len(self.store.get(case["id"])["feedback"]), 1)


if __name__ == "__main__":
    unittest.main()
