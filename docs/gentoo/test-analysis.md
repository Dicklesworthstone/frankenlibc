# Gentoo Test Analysis

This workflow compares package test suites in two modes:

1. Baseline (`FRANKENLIBC_PORTAGE_ENABLE=0`)
2. Instrumented (`FRANKENLIBC_PORTAGE_ENABLE=1`, `FRANKENLIBC_MODE=hardened|strict`)

## Artifacts

- `scripts/gentoo/test-runner.py`
- `scripts/gentoo/compare-results.py`
- `scripts/gentoo/analyze-healing.py`
- `data/gentoo/test-baselines/`

## Dry-Run Validation

```bash
python3 scripts/gentoo/test-runner.py \
  --dry-run \
  --package sys-apps/coreutils \
  --output artifacts/gentoo-tests
```

## Baseline + Instrumented Comparison

`test-runner.py` writes per-package `result.json` plus aggregate `summary.json`.

Comparison output includes:

- `new_failures`
- `new_passes`
- `overhead_percent`
- `verdict` (`PASS|NEUTRAL|IMPROVEMENT|REGRESSION`)

## Standalone Comparison

```bash
python3 scripts/gentoo/compare-results.py \
  baseline.json instrumented.json \
  --output comparison.json
```

## Healing Action Breakdown

```bash
python3 scripts/gentoo/analyze-healing.py \
  /path/to/frankenlibc.jsonl \
  --output healing-summary.json
```

## Telemetry Contract

`test-runner.py` writes two telemetry schemas:

- `gentoo_test_execution_telemetry.v1` in each per-package `result.json`
- `gentoo_test_execution_summary_telemetry.v1` in aggregate `summary.json`

Per-package telemetry binds the baseline log, instrumented log,
`frankenlibc_log`, `healing_actions`, `healing_breakdown`, comparison
verdict, and new failure/pass lists. Summary telemetry repeats the
package-level verdict, total test counts, healing count, and FrankenLibC
log path for every package so audit tooling can cite telemetry without
replaying the full Docker run.
