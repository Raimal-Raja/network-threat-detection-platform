"""Real HTTP harness checks; synthetic response server, not a model benchmark."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from threat_platform.benchmark import benchmark


class BenchmarkTests(unittest.TestCase):
    def run_server(self, fail_after=None):
        class Handler(BaseHTTPRequestHandler):
            count = 0
            def do_POST(self):
                type(self).count += 1
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if fail_after is not None and type(self).count > fail_after:
                    self.send_error(503)
                    return
                prediction = {"model_version": 1, "bundle_sha256": "fixture"}
                result = prediction if self.path == "/predict" else {
                    "predictions": [prediction for _ in data["events"]]}
                raw = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_batch_event_throughput_and_identity(self):
        report = benchmark(self.run_server(), requests=5, warmup=2, batch_size=3)
        self.assertEqual(report["successful_requests"], 5)
        self.assertEqual(report["errors"], 0)
        self.assertEqual(report["model_version"], 1)
        self.assertAlmostEqual(report["events_per_second"],
                               report["successful_requests_per_second"] * 3)
        self.assertGreaterEqual(report["p95_successful_request_latency_ms"], 0)

    def test_failures_are_counted_and_all_failure_p95_is_null(self):
        report = benchmark(self.run_server(fail_after=1), requests=3, warmup=0)
        self.assertEqual(report["errors"], 3)
        self.assertEqual(report["error_rate"], 1)
        self.assertEqual(report["events_per_second"], 0)
        self.assertIsNone(report["p95_successful_request_latency_ms"])

    def test_invalid_configuration(self):
        for kwargs in ({"url": "https://example.com"}, {"url": "http://127.0.0.1", "requests": 0},
                       {"url": "http://127.0.0.1", "batch_size": 257}):
            with self.assertRaises(ValueError):
                benchmark(**kwargs)


if __name__ == "__main__":
    unittest.main()
