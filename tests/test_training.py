import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import numpy as np
from threat_platform.training import train_run, predict_bundle, score_report
from threat_platform.features import threshold_at_fpr, encode
from test_features import fixture


class TrainingTests(unittest.TestCase):
    def test_report_keeps_float64_threshold(self):
        scores = np.asarray([.5, .5, .9], dtype=np.float32)
        cutoff = threshold_at_fpr([0, 0, 1], scores, .01)
        report = score_report([0, 0, 1], scores, cutoff)
        self.assertEqual(report["false_alert_count"], 0)
        self.assertEqual(report["recall"], 1)

    def test_bundle_roundtrip_and_train_only_scaler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            rows = fixture()
            (data / "events.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
            (data / "manifest.json").write_text("{}")
            # Ingestion verification has its own integration tests; isolate training here.
            with patch("threat_platform.training.verify_run",
                       return_value={"events_sha256": "fixture"}):
                report = train_run(data, root / "model", device="cpu")
            self.assertEqual(report["actual_training_device"], "cpu")
            self.assertEqual(report["save_reload_check"], "passed_all_test_rows_on_cpu")
            self.assertFalse(report["production_ready"])
            baseline = json.loads((root / "model/baseline-logistic.json").read_text())
            np.testing.assert_allclose(baseline["scaler_mean"], encode(rows[:12]).mean(axis=0, dtype=np.float64))
            self.assertEqual(len(predict_bundle(root / "model", rows[-4:])), 4)
            with self.assertRaisesRegex(ValueError, "output exists"):
                train_run(data, root / "model")
            with (root / "model/model.json").open("a") as file:
                file.write(" ")
            with self.assertRaisesRegex(ValueError, "checksum"):
                predict_bundle(root / "model", rows[-4:])
