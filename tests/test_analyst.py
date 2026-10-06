"""Real-model explanation and analyst HTTP lifecycle integration tests."""
import json
import math
import shutil
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import test_api
from threat_platform.api import create_app
from threat_platform.tracking import register


FLOW = {"duration_us": 1000, "packets": 104, "bytes": 8200, "protocol": "TCP"}


class AnalystTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_api.ApiTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def application(self, version=1):
        return create_app(self.store, version, self.root / self._testMethodName / "cases.sqlite3")

    def test_create_explain_retry_and_conflicting_event(self):
        with TestClient(self.application()) as client:
            case = client.post("/cases", json={"event_id": "event-1", "flow": FLOW}).json()
            self.assertTrue(case["prediction"]["alert"])
            explanation = case["explanation"]
            self.assertEqual(len(explanation["contributions"]), 6)
            total = explanation["bias"] + sum(c["contribution"] for c in explanation["contributions"])
            self.assertAlmostEqual(total, explanation["raw_margin"], places=4)
            self.assertAlmostEqual(1 / (1 + math.exp(-total)), case["prediction"]["suspicious_score"], places=5)
            self.assertEqual(client.post("/cases", json={"event_id": "event-1", "flow": FLOW}).json()["id"], case["id"])
            conflict = client.post("/cases", json={"event_id": "event-1", "flow": {**FLOW, "bytes": 8201}})
            self.assertEqual(conflict.status_code, 409)
            self.assertEqual(client.get("/cases").json()["total"], 1)

    def test_feedback_conflict_does_not_change_prediction_and_restart_keeps_history(self):
        app = self.application()
        with TestClient(app) as client:
            case = client.post("/cases", json={"event_id": "review-1", "flow": FLOW}).json()
            payload = {"expected_revision": 0, "reviewer": "local", "verdict": "benign", "note": "Check source evidence"}
            saved = client.post("/cases/" + case["id"] + "/feedback", json=payload)
            self.assertEqual(saved.status_code, 200)
            self.assertEqual(saved.json()["prediction"], case["prediction"])
            self.assertEqual(client.post("/cases/" + case["id"] + "/feedback", json=payload).status_code, 409)
        with TestClient(self.application(version=999)) as client:
            restored = client.get("/cases/" + case["id"]).json()
            self.assertEqual(restored["review"], "benign")
            self.assertEqual(len(restored["feedback"]), 1)
            self.assertEqual(client.get("/ready").status_code, 503)
            self.assertEqual(client.get("/analyst/status").json()["case_storage_ready"], True)

    def test_invalid_body_origin_and_missing_case(self):
        with TestClient(self.application()) as client:
            self.assertEqual(client.post("/cases", json={"event_id": "bad", "flow": {**FLOW, "label": 1}}).status_code, 422)
            self.assertEqual(client.post("/cases", json={"event_id": "bad id", "flow": FLOW}).status_code, 422)
            self.assertEqual(client.post("/cases", json={"event_id": "valid", "flow": FLOW}, headers={"Origin": "https://example.com"}).status_code, 403)
            self.assertEqual(client.post("/cases", content=b"x" * 65537).status_code, 413)
            self.assertEqual(client.get("/cases/missing").status_code, 404)
            self.assertEqual(client.get("/cases?limit=0").status_code, 422)
            self.assertEqual(client.get("/cases").json()["total"], 0)

    def test_explanation_failure_does_not_save_partial_case(self):
        app = self.application()
        with TestClient(app) as client:
            with patch.object(app.state.predictor, "explain", side_effect=RuntimeError("injected fault")):
                result = client.post("/cases", json={"event_id": "fault-1", "flow": FLOW})
                self.assertEqual(result.status_code, 503)
            self.assertEqual(client.get("/ready").status_code, 503)
            self.assertEqual(client.get("/cases").json()["total"], 0)

    def test_same_event_under_new_version_is_separate_case(self):
        with TestClient(self.application()) as client:
            original = client.post("/cases", json={"event_id": "shared-event", "flow": FLOW}).json()
        changed = self.root / "case-version-2"
        shutil.copytree(self.bundle, changed)
        metadata = json.loads((changed / "metadata.json").read_text())
        metadata["threshold"] = .75
        (changed / "metadata.json").write_text(json.dumps(metadata))
        version = register(changed, self.store)["version"]
        with TestClient(self.application(version)) as client:
            latest = client.post("/cases", json={"event_id": "shared-event", "flow": FLOW}).json()
            self.assertNotEqual(original["id"], latest["id"])
            self.assertEqual(latest["prediction"]["model_version"], version)
            self.assertEqual(client.get("/cases").json()["total"], 2)

    def test_dashboard_assets_are_local_and_feedback_validation_is_bounded(self):
        with TestClient(self.application()) as client:
            page = client.get("/analyst")
            self.assertEqual(page.status_code, 200)
            self.assertIn("default-src 'self'", page.headers["content-security-policy"])
            self.assertEqual(client.get("/assets/analyst.js").status_code, 200)
            self.assertEqual(client.get("/assets/analyst.css").status_code, 200)
            case = client.post("/cases", json={"event_id": "bounds", "flow": FLOW}).json()
            base = {"expected_revision": 0, "reviewer": "local", "verdict": "uncertain"}
            for payload in ({**base, "note": "x" * 2001}, {**base, "expected_revision": True}, {**base, "verdict": "approved"}):
                self.assertEqual(client.post("/cases/" + case["id"] + "/feedback", json=payload).status_code, 422)


if __name__ == "__main__":
    unittest.main()
