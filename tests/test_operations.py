"""Behavioral checks for telemetry, replay failures, rejection and safe rollback."""
import hashlib
import json
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
import test_api
from fastapi.testclient import TestClient
from threat_platform.api import create_app
from threat_platform.monitoring import Monitor, Telemetry
from threat_platform.demo import run_demo
from threat_platform.replay import drift, evaluate, replay, local_url
from threat_platform.deployment import activate, rollback, state, gate, selected_version, export_store
from threat_platform.tracking import register, show
from threat_platform.features import split_rows
from threat_platform.training import predict_bundle, score_report

FLOW = {"duration_us": 1000, "packets": 12, "bytes": 4096, "protocol": "TCP"}

class MonitorTests(unittest.TestCase):
    def test_bounded_success_latency_and_error_counts(self):
        m = Monitor(capacity=2)
        for seconds in (.001, .002, .003):
            m.record(200, seconds, True)
        m.record(422, .1, True)
        m.record(503, .2, True)
        report = m.snapshot()
        self.assertEqual(report["successful_prediction_latency_samples"], 2)
        self.assertEqual(report["p95_successful_prediction_request_ms"], 3)
        self.assertEqual(report["counts"]["prediction_failures"], 2)
        self.assertEqual(report["counts"]["invalid_requests"], 1)
        self.assertEqual(report["counts"]["server_errors"], 1)

    def test_exception_after_headers_is_counted_as_failure(self):
        import asyncio
        async def broken(scope, receive, send):
            await send({"type": "http.response.start", "status": 200})
            raise RuntimeError("failed response")
        async def send(message):
            pass
        async def receive():
            return {"type": "http.request", "body": b""}
        monitor = Monitor()
        with self.assertRaises(RuntimeError):
            asyncio.run(Telemetry(broken, monitor)({"type": "http", "path": "/predict"}, receive, send))
        self.assertEqual(monitor.snapshot()["counts"]["server_errors"], 1)
        self.assertEqual(monitor.snapshot()["successful_prediction_latency_samples"], 0)

class ReplayTests(unittest.TestCase):
    def test_drift_unchanged_and_obvious_shift(self):
        rows = [FLOW]*20
        self.assertFalse(drift(rows, rows)["investigate"])
        self.assertTrue(drift(rows, [{**FLOW, "packets": 10000}]*20)["investigate"])

    def test_partial_day_not_extrapolated_and_bad_response(self):
        rows = [{**FLOW, "label": i % 2, "timestamp": f"2026-01-01T00:00:0{i}+00:00"} for i in range(4)]
        preds = [{"suspicious_score": .8 if r["label"] else .1, "alert": bool(r["label"])} for r in rows]
        result = evaluate(rows, preds, .5)
        self.assertEqual(result["metrics"]["recall"], 1)
        self.assertEqual(result["metrics"]["false_positive_rate"], 0)
        self.assertIsNone(result["false_alerts_per_day"])
        with self.assertRaises(ValueError):
            evaluate(rows, [{**p, "alert": False} for p in preds], .5)

    def test_no_remote_or_credential_urls(self):
        for url in ("https://example.com", "http://example.com", "http://user:pass@localhost", "http://localhost?x=1"):
            with self.assertRaises(ValueError):
                local_url(url)

    def test_replay_failure_and_shift_suppress_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            rows = [{**FLOW, "event_id": str(i), "label": i % 2,
                     "timestamp": f"2026-01-01T00:{i//60:02}:{i%60:02}+00:00"} for i in range(120)]
            (path/"events.jsonl").write_text("\n".join(json.dumps(r) for r in rows)+"\n")
            def reply(url, endpoint, payload=None):
                if endpoint == "/model":
                    return {"model_version": 1, "bundle_sha256": "abc", "threshold": .5}
                return {"count": len(payload["events"]), "predictions": [
                    {"model_version": 1, "bundle_sha256": "abc", "threshold": .5,
                     "suspicious_score": .1, "alert": False} for _ in payload["events"]]}
            with patch("threat_platform.replay.verify_run", return_value={"events_sha256": "fixture"}), patch("threat_platform.replay.http", side_effect=reply):
                self.assertIsNotNone(replay(path, "http://localhost", 24)["detection"])
                self.assertIsNone(replay(path, "http://localhost", 24, shift=10)["detection"])
            def failing(url, endpoint, payload=None):
                if endpoint == "/model":
                    return reply(url, endpoint)
                raise OSError("unavailable")
            with patch("threat_platform.replay.verify_run", return_value={"events_sha256": "fixture"}), patch("threat_platform.replay.http", side_effect=failing):
                result = replay(path, "http://localhost", 24)
                self.assertEqual(result["successful_events"], 0)
                self.assertTrue(result["errors"])
                self.assertIsNone(result["detection"])
                self.assertIsNone(result["p95_successful_batch_latency_ms"])

class OperationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_api.ApiTests.setUpClass.__func__(cls)
        changed = cls.root/"candidate"
        shutil.copytree(cls.bundle, changed)
        metadata = json.loads((changed/"metadata.json").read_text())
        metadata["threshold"] = .99
        (changed/"metadata.json").write_text(json.dumps(metadata))
        metrics = json.loads((changed/"metrics.json").read_text())
        partitions = split_rows([json.loads(line) for line in (cls.root/"data"/"events.jsonl").read_text().splitlines()])
        metrics["models"]["xgboost"]["threshold"] = .99
        for name in ("validation", "test"):
            part = partitions[name]
            scores = [p["suspicious_score"] for p in predict_bundle(changed, part)]
            metrics["models"]["xgboost"][name] = score_report([r["label"] for r in part], scores, .99)
        (changed/"metrics.json").write_text(json.dumps(metrics))
        cls.candidate = register(changed, cls.store)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def deployment_path(self):
        return self.root/self._testMethodName/"state.sqlite3"

    def test_activation_rollback_revision_and_pinned_process(self):
        path = self.deployment_path()
        with self.assertRaises(ValueError):
            activate(path, self.store, 1, 0)
        first = activate(path, self.store, 1, 0, True)
        self.assertEqual(first["revision"], 1)
        with TestClient(create_app(self.store, 1)) as client:
            second = activate(path, self.store, 2, 1, True)
            self.assertEqual(client.get("/ready").json()["model_version"], 1)
            with self.assertRaises(ValueError):
                activate(path, self.store, 1, 1, True)
            restored = rollback(path, self.store, 2, True)
            self.assertEqual(restored["version"], 1)
            self.assertEqual(restored["revision"], 3)
            self.assertEqual(selected_version(path, self.store), 1)
            self.assertEqual(second["version"], 2)

    def test_bad_version_leaves_state_unchanged(self):
        path = self.deployment_path()
        first = activate(path, self.store, 1, 0, True)
        with self.assertRaises(ValueError):
            activate(path, self.store, 999, 1, True)
        self.assertEqual(state(path), first)
        with self.assertRaises(ValueError):
            rollback(path, self.store, 1, True)

    def test_corrupt_previous_version_cannot_rollback(self):
        path = self.deployment_path()
        isolated = self.root/"isolated"
        register(self.bundle, isolated)
        register(self.root/"candidate", isolated)
        activate(path, isolated, 1, 0, True)
        before = activate(path, isolated, 2, 1, True)
        (isolated/"bundles"/self.record["bundle_sha256"]/"model.json").write_text("{}")
        with self.assertRaises(ValueError):
            rollback(path, isolated, 2, True)
        self.assertEqual(state(path), before)

    def test_worse_model_and_mismatched_benchmark_rejected(self):
        b = {"model_version": 2, "bundle_sha256": self.candidate["bundle_sha256"],
             "requests": 100, "successful_requests": 100, "errors": 0,
             "p95_successful_request_latency_ms": 5, "events_per_second": 200}
        report = gate(self.store, 2, b)
        self.assertFalse(report["checks"]["heldout_recall"])
        self.assertTrue(report["checks"]["metric_threshold_identity"])
        self.assertEqual(report["decision"], "reject_production_promotion")
        self.assertIn("independent_capture_evidence", report["failed_checks"])
        self.assertFalse(report["production_ready"])
        b["bundle_sha256"] = "wrong"
        b["p95_successful_request_latency_ms"] = float("nan")
        self.assertFalse(gate(self.store, 2, b)["checks"]["benchmark_identity"])
        self.assertFalse(gate(self.store, 2, b)["checks"]["latency"])

    def test_startup_reads_simulation_state_and_explicit_version_wins(self):
        path = self.deployment_path()
        activate(path, self.store, 2, 0, True)
        with patch.dict("os.environ", {"THREAT_DEPLOYMENT_DB": str(path)}, clear=True):
            with TestClient(create_app(self.store)) as client:
                self.assertEqual(client.get("/ready").json()["model_version"], 2)
            with TestClient(create_app(self.store, 1)) as client:
                self.assertEqual(client.get("/ready").json()["model_version"], 1)

    def test_monitor_excludes_scrapes_and_records_validation(self):
        with TestClient(create_app(self.store, 1)) as client:
            client.get("/monitor")
            client.get("/ready")
            client.post("/predict", json=FLOW)
            client.post("/predict", json={**FLOW, "bytes": -1})
            stats = client.get("/monitor").json()
            self.assertEqual(stats["counts"]["requests"], 2)
            self.assertEqual(stats["counts"]["prediction_failures"], 1)
            self.assertEqual(stats["successful_prediction_latency_samples"], 1)
            self.assertNotIn("bytes", json.dumps(stats))

    def test_demo_rejects_model_change_between_measurements(self):
        expected = {"model_version": 1, "bundle_sha256": self.record["bundle_sha256"]}
        baseline = {**expected, "errors": [], "invalid_input_probe": {"passed": True}}
        changed = {**baseline, "bundle_sha256": "changed"}
        output = self.root/"model-change-demo"
        with patch("threat_platform.demo.http", return_value=expected), \
             patch("threat_platform.demo.replay", side_effect=[baseline, changed]), \
             patch("threat_platform.demo.benchmark", return_value=expected):
            with self.assertRaisesRegex(ValueError, "model changed"):
                run_demo(self.root/"data", self.store, 1, "http://localhost", output)
        self.assertFalse(output.exists())

    def test_container_export_preserves_identity_and_version(self):
        output = self.root/"exported-models"
        before = (self.store/"bundles"/self.candidate["bundle_sha256"]).stat().st_mode
        export_store(self.store, 2, output)
        self.assertEqual(show(output, 2), self.candidate)
        self.assertEqual((self.store/"bundles"/self.candidate["bundle_sha256"]).stat().st_mode, before)
        self.assertEqual((output/"bundles"/self.candidate["bundle_sha256"]).stat().st_mode & 0o444, 0o444)
        with TestClient(create_app(output, 2)) as client:
            self.assertEqual(client.get("/ready").json()["bundle_sha256"], self.candidate["bundle_sha256"])
        with self.assertRaises(ValueError):
            export_store(self.store, 2, output)
