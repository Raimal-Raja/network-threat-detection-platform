"""CI end-to-end smoke; synthetic fixture isolated from public-data measurements."""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
import test_api
from threat_platform.demo import run_demo
from threat_platform.deployment import activate, rollback
from threat_platform.tracking import register
import shutil

test_api.ApiTests.setUpClass()
fixture = test_api.ApiTests
env = dict(os.environ, THREAT_MODEL_STORE=str(fixture.store), THREAT_MODEL_VERSION="1",
           THREAT_CASE_DB=str(fixture.root/"cases.sqlite3"))
server = subprocess.Popen([sys.executable, "-m", "uvicorn", "threat_platform.api:app",
                           "--host", "127.0.0.1", "--port", "8766"], env=env)
try:
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:8766/ready", timeout=1).close()
            break
        except OSError:
            time.sleep(.5)
    else:
        raise RuntimeError("smoke server unready")
    # Synthetic training fixture manifest is intentionally not public ingestion provenance.
    # Public checksum validation has separate tests. This bypass exists only in CI smoke.
    with patch("threat_platform.replay.verify_run", return_value={"events_sha256": "synthetic-ci-fixture"}):
        report = run_demo(fixture.root/"data", fixture.store, 1,
                          "http://127.0.0.1:8766", Path("artifacts/verification/operations-demo"), 24)
    assert report["promotion"] == "reject_production_promotion"
    deployment = fixture.root/"deployment.sqlite3"
    activate(deployment, fixture.store, 1, 0, True)
    candidate = fixture.root/"candidate"
    shutil.copytree(fixture.bundle, candidate)
    metadata = json.loads((candidate/"metadata.json").read_text())
    metadata["threshold"] = .99
    (candidate/"metadata.json").write_text(json.dumps(metadata))
    register(candidate, fixture.store)
    activate(deployment, fixture.store, 2, 1, True)
    assert rollback(deployment, fixture.store, 2, True)["version"] == 1
    print("Operations smoke passed: baseline, shift, invalid input, monitoring, analyst review, rejection, rollback.")
finally:
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
    fixture.tearDownClass()
