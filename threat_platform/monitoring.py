"""Bounded, process-local service telemetry; no request bodies or identifiers."""
import math
import threading
import time
from collections import Counter, deque

class Monitor:
    def __init__(self, capacity=1024):
        self.lock = threading.Lock()
        self.counts = Counter()
        self.latencies = deque(maxlen=capacity)
        self.started = time.monotonic()

    def record(self, status, seconds, prediction):
        with self.lock:
            self.counts["requests"] += 1
            self.counts["server_errors"] += int(status >= 500 or status == 0)
            self.counts["invalid_requests"] += int(status in (413, 422))
            if prediction:
                self.counts["prediction_requests"] += 1
                self.counts["prediction_failures"] += int(not 200 <= status < 300)
                if 200 <= status < 300:
                    self.latencies.append(seconds * 1000)

    def snapshot(self):
        with self.lock:
            values = sorted(self.latencies)
            counts = dict(self.counts)
        return {"simulated": True, "production_ready": False, "scope": "this_process_since_start",
                "uptime_seconds": time.monotonic() - self.started, "counts": counts,
                "successful_prediction_latency_samples": len(values),
                "p95_successful_prediction_request_ms": values[math.ceil(.95 * len(values))-1] if values else None,
                "latency_window_capacity": self.latencies.maxlen,
                "limitations": "ASGI request duration; includes validation/serialization, excludes client network. Resets on restart; failures excluded from latency but counted separately."}

class Telemetry:
    def __init__(self, app, monitor):
        self.app, self.monitor = app, monitor

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] in ("/monitor", "/health", "/ready") or scope["path"].startswith("/assets/"):
            return await self.app(scope, receive, send)
        status, start = 0, time.perf_counter()
        async def observed(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)
        try:
            await self.app(scope, receive, observed)
        except BaseException:
            status = 0
            raise
        finally:
            self.monitor.record(status, time.perf_counter() - start,
                                scope["path"] in ("/predict", "/predict/batch"))
