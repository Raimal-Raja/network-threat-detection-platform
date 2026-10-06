# Step 8 verification

Verified on 2026-10-07. [GitHub CI](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707) passed **83 unit/API tests in 2.713 seconds**, JavaScript syntax, Chromium desktop/mobile workflow, live operations smoke, Compose validation, Docker build, and case persistence across container restart. Tested implementation commit: `6621ed647f2dd163d97222d4404f028228fd53d8`. Subsequent documentation/evidence changes do not alter this implementation.

[CI proof artifacts](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707/artifacts/11439677359) contain screenshots, browser results, synthetic reports and container results; retention is seven days. These functional CI fixtures are distinct from the real public-data replay below.

## Public-data replay

A separate local end-to-end run loaded the user's saved bundle c771366e25de10a56865ff45f43fcbc53729c7aa42995c237a61e2c825531b39 on CPU and verified the original CTU-13 scenario 11 processed checksums. All 2,175 selected test events succeeded.

Average precision was 0.9999907457; trapezoidal PR-AUC 0.9999928927; recall 100%; false positives 24/382 (FPR 6.2827%) at the frozen threshold 0.0182791222. Baseline drift flag was false, the 10x packet/byte scenario flag was true, and the invalid probe returned 422. Shifted detection metrics were suppressed.

Replay used batch size 32, concurrency 1 and one server worker. Successful throughput was 1,953.68 events/sec with batch-request p95 35.73ms on an Intel i5-1235U, Windows x64, Python 3.12.14. These are one local run's measurements, not a production SLA. Partial-day daily counts are included; false alerts/day remains null without complete exposure evidence.

See [measured example](../10-demonstration/measured-example.json) and [full aggregate reports](../10-demonstration/example-reports/README.md). Reused within-capture evaluation, overlapping hosts and excluded unknown labels remain limitations. No independent validation or production effectiveness is claimed.
