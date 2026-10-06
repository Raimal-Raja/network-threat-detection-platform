# Step 10 verification


**The end-to-end demonstration is complete; independent operational evaluation is pending.**

Verified on 2026-10-07. [GitHub CI](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707) passed **83 unit/API tests in 2.713 seconds**, JavaScript syntax, Chromium desktop/mobile workflow, live operations smoke, Compose validation, Docker build, and case persistence across container restart. Tested implementation commit: `6621ed647f2dd163d97222d4404f028228fd53d8`. Subsequent documentation/evidence changes do not alter this implementation.

[CI proof artifacts](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707/artifacts/11439677359) contain screenshots, browser results, synthetic reports and container results; retention is seven days. These functional CI fixtures are distinct from the real public-data replay below.

## Actual end-to-end run

The local command path ran on verified CTU-13 data and the saved Colab bundle without retraining. It completed unchanged replay, 10x shifted traffic, invalid input rejection, individual HTTP benchmark, production gate rejection, a synthetic uncertain analyst review preserving the original prediction, and a monitoring snapshot.

The test used a separate temporary case database and registry copy, preserving the user's original local registry/cases. Only aggregate reports are checked in; no weights, raw data or real review notes are published.

[Full example reports](example-reports/README.md) contain all six JSON outputs and their SHA-256 checksums. [Measured example](measured-example.json) records hardware, scope and selected results. The gate was also rechecked after adding threshold-evidence binding; checksums were refreshed for that report.

## Limits and remaining evidence

Independent capture evaluation is not implemented or claimed complete. Scenario 11 is the already-inspected development holdout; background/unknown labels are excluded, hosts overlap, and continuous-day exposure is unproven. False alerts/day remains null and production promotion remains rejected.

Follow the independent evaluation protocol in this step's README before operational claims. The platform uses SQLite; MLflow/PostgreSQL, authentication and signed evidence are future integrations, not hidden prerequisites or completed features.
