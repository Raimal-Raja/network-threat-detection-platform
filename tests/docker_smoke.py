"""CI container behavior verification using synthetic weights, never user artifacts."""
import json
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
import test_api

test_api.ApiTests.setUpClass()
fixture = test_api.ApiTests
name = "threat-platform-smoke"
try:
    subprocess.run(["docker", "run", "-d", "--name", name, "--read-only",
                    "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "-p", "127.0.0.1:8767:8000",
                    "-e", "THREAT_MODEL_STORE=/models", "-e", "THREAT_MODEL_VERSION=1",
                    "-e", "THREAT_CASE_DB=/app/artifacts/analyst/cases.sqlite3",
                    "-v", str(fixture.store)+":/models:ro",
                    "-v", "threat-smoke-cases:/app/artifacts/analyst",
                    "threat-platform:ci"], check=True)
    for _ in range(60):
        try:
            ready = json.load(urllib.request.urlopen("http://127.0.0.1:8767/ready", timeout=1))
            break
        except OSError:
            time.sleep(1)
    else:
        raise RuntimeError("container model unready")
    assert ready["bundle_sha256"] == fixture.record["bundle_sha256"]
    flow = {"duration_us": 1000, "packets": 104, "bytes": 8200, "protocol": "TCP"}
    request = urllib.request.Request("http://127.0.0.1:8767/cases",
              data=json.dumps({"event_id": "container-fixture", "flow": flow}).encode(),
              headers={"Content-Type": "application/json"})
    case = json.load(urllib.request.urlopen(request))
    subprocess.run(["docker", "restart", name], check=True)
    for _ in range(60):
        try:
            saved = json.load(urllib.request.urlopen("http://127.0.0.1:8767/cases/"+case["id"], timeout=1))
            break
        except OSError:
            time.sleep(1)
    else:
        raise RuntimeError("container persisted case unavailable")
    assert saved["prediction"] == case["prediction"]
    proof = Path("artifacts/verification")
    proof.mkdir(parents=True, exist_ok=True)
    (proof/"container-results.json").write_text(json.dumps(
        {"simulated": True, "production_ready": False, "read_only_root": True,
         "model_loaded": True, "case_survived_restart": True}, indent=2)+"\n")
    print("Container smoke passed: ready, prediction, case persistence on restart.")
finally:
    subprocess.run(["docker", "logs", name], check=False)
    subprocess.run(["docker", "rm", "-f", name], check=False)
    subprocess.run(["docker", "volume", "rm", "threat-smoke-cases"], check=False)
    fixture.tearDownClass()
