# Step 9 verification

Verified on 2026-10-07. [GitHub CI](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707) passed **83 unit/API tests in 2.713 seconds**, JavaScript syntax, Chromium desktop/mobile workflow, live operations smoke, Compose validation, Docker build, and case persistence across container restart. Tested implementation commit: `6621ed647f2dd163d97222d4404f028228fd53d8`. Subsequent documentation/evidence changes do not alter this implementation.

[CI proof artifacts](https://github.com/Raimal-Raja/network-threat-detection-platform/actions/runs/37520693707/artifacts/11439677359) contain screenshots, browser results, synthetic reports and container results; retention is seven days. These functional CI fixtures are distinct from the real public-data replay below.

## Deployment behavior

Tests load real synthetic XGBoost weights, measure an actual candidate threshold regression, reject its low recall, check metric/threshold binding, reject unknown/corrupt versions without replacing active state, detect stale revisions, preserve a running pinned version and restore the previous verified version.

The first container attempt could not read private registry snapshot directories. The implemented export-model command now creates a separate verified readable store while preserving the source registry's permissions and the selected version/fingerprint. The successful container smoke used a read-only root filesystem, dropped capabilities, loopback port and named case volume; its original prediction survived restart.

The built CI image ID was sha256:53c75b50d29b043fda0754c823c73b416a8b6bbe61d3cfa0c82b6f3db7095112. The image/base tag is not a published pinned release.

## Public model rejection

The local public-data model's 100-request individual benchmark completed without errors: 56.60 requests/sec, p95 32.27ms, 10 warmups, CPU inference, one worker. The gate rejected held-out FPR, benign support, independent capture evidence and complete-day exposure evidence. Matching benchmark and frozen-threshold identity checks passed.

This is explicit simulation activation/rollback, not production approval, hot reload, distributed orchestration or authentication. The local Docker engine was unavailable; Linux CI supplied container execution evidence.
