"""Lifecycle and integrity tests; no numerical dependencies required."""
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from threat_platform.tracking import register, show, versions


class TrackingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "source"
        self.bundle.mkdir()
        self.store = self.root / "tracking"
        # Contract fixture, not a real trained model or evaluation result.
        model = b'{"fixture": true}'
        (self.bundle / "model.json").write_bytes(model)
        self.metadata = {
            "artifact_version": 1, "simulated": True, "production_ready": False,
            "model_sha256": hashlib.sha256(model).hexdigest(),
            "feature_version": "completed-flow-v1", "feature_names": ["fixture"],
            "packages": {}, "code_sha256": {}, "events_sha256": "fixture",
            "model_parameters": {}, "threshold": 0.5}
        self.save_metadata()
        (self.bundle / "metrics.json").write_text(json.dumps({
            "simulated": True, "production_ready": False,
            "save_reload_check": "passed_all_test_rows_on_cpu", "models": {"xgboost": {}}}))
        for name in ("split-audit.json", "baseline-logistic.json", "data-manifest.json"):
            (self.bundle / name).write_text("{}")
        (self.bundle / "features.py").write_text("# fixture")
        (self.bundle / "README.md").write_text("Fixture only")

    def save_metadata(self):
        (self.bundle / "metadata.json").write_text(json.dumps(self.metadata))

    def test_snapshot_survives_source_deletion_and_duplicate_import(self):
        first = register(self.bundle, self.store, "GPU demonstration")
        second = register(self.bundle, self.store, "does not change original note")
        self.assertEqual(first, second)
        for file in self.bundle.iterdir():
            file.unlink()
        self.bundle.rmdir()
        restored = show(self.store, 1)
        self.assertEqual(restored["note"], "GPU demonstration")
        self.assertFalse(restored["production_ready"])
        self.assertEqual(len(versions(self.store)), 1)

    def test_threshold_change_is_new_version(self):
        first = register(self.bundle, self.store)
        self.metadata["threshold"] = 0.7
        self.save_metadata()
        second = register(self.bundle, self.store)
        self.assertEqual([first["version"], second["version"]], [1, 2])
        self.assertNotEqual(first["bundle_sha256"], second["bundle_sha256"])

    def test_corrupt_model_and_false_approval_rejected(self):
        (self.bundle / "model.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "checksum"):
            register(self.bundle, self.store)
        self.metadata["production_ready"] = True
        self.save_metadata()
        with self.assertRaisesRegex(ValueError, "approve"):
            register(self.bundle, self.store)

    def test_registered_metadata_tampering_is_detected(self):
        row = register(self.bundle, self.store)
        snapshot = self.store / "bundles" / row["bundle_sha256"]
        value = json.loads((snapshot / "metadata.json").read_text())
        value["threshold"] = 0.9
        (snapshot / "metadata.json").write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "changed"):
            show(self.store, 1)
        with self.assertRaises(ValueError):
            register(self.bundle, self.store)

    def test_missing_files_nonfinite_json_and_unknown_version(self):
        (self.bundle / "metrics.json").write_text('{"value": NaN}')
        with self.assertRaisesRegex(ValueError, "nonfinite"):
            register(self.bundle, self.store)
        (self.bundle / "metrics.json").unlink()
        with self.assertRaisesRegex(ValueError, "eight"):
            register(self.bundle, self.store)
        with self.assertRaisesRegex(ValueError, "unknown"):
            show(self.store, 99)

    def test_concurrent_duplicate_registration(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            rows = list(pool.map(lambda _: register(self.bundle, self.store), range(2)))
        self.assertEqual([r["version"] for r in rows], [1, 1])
        self.assertEqual(len(versions(self.store)), 1)


if __name__ == "__main__":
    unittest.main()
