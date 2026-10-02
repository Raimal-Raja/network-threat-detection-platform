"""HTTP contract tests against an actual tiny, simulated XGBoost bundle."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from fastapi.testclient import TestClient

from threat_platform.api import create_app
from threat_platform.tracking import register
from threat_platform.training import train_run, predict_bundle


FLOW = {"duration_us": 1000, "packets": 12, "bytes": 4096, "protocol": "TCP"}


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        data = cls.root / "data"
        data.mkdir()
        rows = []
        for i in range(120):
            label = i % 2
            rows.append({"event_id": str(i), "timestamp": f"2026-01-01T00:{i // 60:02}:{i % 60:02}+00:00",
                         "duration_us": 1000, "packets": 4 + label * 100, "bytes": 200 + label * 8000,
                         "protocol": "TCP", "label": label,
                         "source_host_id": "fixture-a", "destination_host_id": "fixture-b"})
        raw = "\n".join(json.dumps(row) for row in rows) + "\n"
        (data / "events.jsonl").write_text(raw)
        (data / "manifest.json").write_text('{"fixture": true}')
        cls.bundle = cls.root / "model"
        # Isolate ingestion; its real checksum path has separate coverage.
        with patch("threat_platform.training.verify_run",
                   return_value={"events_sha256": hashlib.sha256(raw.encode()).hexdigest()}):
            train_run(data, cls.bundle, device="cpu")
        cls.store = cls.root / "tracking"
        cls.record = register(cls.bundle, cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_single_batch_and_offline_scores_match(self):
        expected = predict_bundle(self.bundle, [FLOW])[0]
        with TestClient(create_app(self.store, 1)) as client:
            single = client.post("/predict", json=FLOW)
            self.assertEqual(single.status_code, 200)
            actual = single.json()
            self.assertAlmostEqual(actual["suspicious_score"], expected["suspicious_score"], places=7)
            self.assertEqual(actual["alert"], expected["alert"])
            self.assertEqual(actual["model_version"], 1)
            self.assertEqual(actual["bundle_sha256"], self.record["bundle_sha256"])
            self.assertFalse(actual["production_ready"])
            batch = client.post("/predict/batch", json={"events": [FLOW, FLOW]}).json()
            self.assertEqual(batch["predictions"], [actual, actual])

    def test_strict_validation(self):
        invalid = [
            {**FLOW, "packets": True}, {**FLOW, "packets": "12"},
            {**FLOW, "packets": 12.0}, {**FLOW, "packets": -1},
            {**FLOW, "bytes": 2**63}, {**FLOW, "duration_us": 86_400_000_001},
            {**FLOW, "protocol": "tcp"}, {**FLOW, "protocol": "OTHER"},
            {**FLOW, "label": 1}, {**FLOW, "timestamp": "anything"},
            {k: v for k, v in FLOW.items() if k != "bytes"}]
        with TestClient(create_app(self.store, 1)) as client:
            for row in invalid:
                with self.subTest(row=row):
                    self.assertEqual(client.post("/predict", json=row).status_code, 422)
            self.assertEqual(client.post("/predict", content="{", headers={"Content-Type": "application/json"}).status_code, 422)
            self.assertEqual(client.post("/predict", content='{"duration_us":NaN,"packets":1,"bytes":2,"protocol":"TCP"}', headers={"Content-Type": "application/json"}).status_code, 422)

    def test_batch_bounds_and_atomic_validation(self):
        with TestClient(create_app(self.store, 1)) as client:
            for events in ([], [FLOW] * 257, [FLOW, {**FLOW, "bytes": -1}]):
                self.assertEqual(client.post("/predict/batch", json={"events": events}).status_code, 422)
            valid = client.post("/predict/batch", json={"events": [FLOW] * 256})
            self.assertEqual(valid.status_code, 200)
            self.assertEqual(valid.json()["count"], 256)

    def test_actual_body_limit_ignores_false_content_length(self):
        with TestClient(create_app(self.store, 1)) as client:
            response = client.post("/predict", content=b"x" * 65537,
                                   headers={"Content-Type": "application/json", "Content-Length": "1"})
            self.assertEqual(response.status_code, 413)

    def test_health_readiness_and_model_details(self):
        with TestClient(create_app(self.store, 1)) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/ready").json()["model_version"], 1)
            self.assertFalse(client.get("/model").json()["production_ready"])
            self.assertIn("/predict/batch", client.get("/openapi.json").json()["paths"])

    def test_unknown_version_is_alive_but_unready(self):
        with TestClient(create_app(self.store, 999)) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            for path in ("/ready", "/model"):
                self.assertEqual(client.get(path).status_code, 503)
            self.assertEqual(client.post("/predict", json=FLOW).status_code, 503)

    def test_corrupt_registered_model_fails_startup(self):
        isolated = self.root / "corrupt-tracking"
        record = register(self.bundle, isolated)
        path = isolated / "bundles" / record["bundle_sha256"] / "model.json"
        path.write_text("{}")
        with TestClient(create_app(isolated, 1)) as client:
            self.assertEqual(client.get("/ready").status_code, 503)
            self.assertEqual(client.get("/health").status_code, 200)

    def test_unsupported_feature_contract_fails_startup(self):
        import shutil
        changed = self.root / "wrong-feature-model"
        shutil.copytree(self.bundle, changed)
        metadata = json.loads((changed / "metadata.json").read_text())
        metadata["feature_version"] = "unsupported-version"
        (changed / "metadata.json").write_text(json.dumps(metadata))
        isolated = self.root / "wrong-feature-tracking"
        register(changed, isolated)
        with TestClient(create_app(isolated, 1)) as client:
            self.assertEqual(client.get("/ready").status_code, 503)

    def test_runtime_invalid_scores_remove_readiness(self):
        app = create_app(self.store, 1)
        with TestClient(app) as client:
            with patch.object(app.state.predictor.model, "predict_proba",
                              return_value=np.array([[0.0, np.nan]])):
                self.assertEqual(client.post("/predict", json=FLOW).status_code, 503)
            self.assertEqual(client.get("/ready").status_code, 503)

    def test_new_version_does_not_change_running_model(self):
        with TestClient(create_app(self.store, 1)) as client:
            changed = self.root / "new-model"
            if not changed.exists():
                import shutil
                shutil.copytree(self.bundle, changed)
                metadata = json.loads((changed / "metadata.json").read_text())
                metadata["threshold"] = 0.75
                (changed / "metadata.json").write_text(json.dumps(metadata))
            register(changed, self.store)
            self.assertEqual(client.get("/model").json()["model_version"], 1)


if __name__ == "__main__":
    unittest.main()
