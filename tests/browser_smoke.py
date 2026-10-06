"""Headless analyst workflow proof using a real synthetic model, never user data."""
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
from test_api import ApiTests
from playwright.sync_api import sync_playwright

ApiTests.setUpClass()
proof = Path("artifacts/verification")
proof.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, THREAT_MODEL_STORE=str(ApiTests.store), THREAT_MODEL_VERSION="1",
           THREAT_CASE_DB=str(ApiTests.root / "browser-cases.sqlite3"))
server = subprocess.Popen([sys.executable, "-m", "uvicorn", "threat_platform.api:app",
                           "--host", "127.0.0.1", "--port", "8765"], env=env)
try:
    for attempt in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8765/ready", timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(.5)
    else:
        raise RuntimeError("Browser test model never became ready")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("http://127.0.0.1:8765/analyst")
        page.get_by_role("button", name="Assess & save").wait_for(state="visible")
        page.wait_for_function("!document.getElementById('assess-button').disabled")
        page.get_by_label("Event ID", exact=True).fill("browser-demo-001")
        page.get_by_role("button", name="Assess & save").click()
        page.locator("#case-title").filter(has_text="browser-demo-001").wait_for()
        assert page.locator("#contributions .contribution").count() == 6
        page.get_by_label("Reviewer alias").fill("smoke-analyst")
        page.get_by_label("Verdict", exact=True).select_option("benign")
        note = "Simulated review: verify capture evidence. <script>window.__injected=true</script>"
        page.get_by_label("Evidence and notes").fill(note)
        page.get_by_role("button", name="Save review").click()
        page.locator("#history").get_by_text(note, exact=True).wait_for()
        assert not page.evaluate("Boolean(window.__injected)")
        assert page.locator("#decision").inner_text() == "Alert"
        page.screenshot(path=str(proof / "analyst-desktop.png"), full_page=True)
        page.reload()
        page.get_by_role("button").filter(has_text="browser-demo-001").click()
        page.locator("#history").get_by_text(note, exact=True).wait_for()
        page.get_by_label("Review", exact=True).select_option("benign")
        page.locator("#queue-count").filter(has_text="1 matching case").wait_for()
        page.set_viewport_size({"width": 390, "height": 844})
        page.screenshot(path=str(proof / "analyst-mobile.png"), full_page=True)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert not errors, errors
        (proof / "browser-results.json").write_text(json.dumps({
            "simulated": True, "production_ready": False, "browser": "Chromium",
            "workflow": "assess, explain, review, preserve original alert, reload, filter",
            "literal_note_rendering": "passed", "horizontal_overflow_mobile": False,
            "page_errors": errors, "model_fixture_rows": 120}, indent=2))
        browser.close()
    print("Browser workflow passed; desktop/mobile screenshots saved.")
finally:
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()
    ApiTests.tearDownClass()
