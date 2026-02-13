# FrankenLibC Gentoo E2E Tests

End-to-end tests for validating the FrankenLibC Gentoo integration pipeline.

## Overview

These tests validate the complete flow from Docker image creation through package building, testing, and result reporting. They catch integration issues that unit tests miss.

## Prerequisites

- Docker installed and running
- ~10GB disk space for Docker images and build artifacts
- Internet access for package downloads

## Quick Start

```bash
# Run all E2E tests
./run_all_e2e.sh

# Run only fast tests (< 10 minutes total)
./run_all_e2e.sh --fast

# Run a specific test
./run_all_e2e.sh single_package
```

## Test Scenarios

| Test | Description | Runtime |
|------|-------------|---------|
| `single_package` | Build one package with FrankenLibC | ~5 min |
| `build_wave` | Parallel build of 3 packages | ~10 min |
| `test_suite` | Baseline vs instrumented comparison | ~15 min |
| `full_pipeline` | Complete pipeline with 5 packages | ~30 min |
| `failure_recovery` | Failure handling and resume | ~10 min |
| `progress_reporting` | Progress tracking and webhooks | ~5 min |

## Test Details

### Single Package Build (`test_single_package.sh`)

Tests the complete flow for building one package:
1. Verify Docker image exists
2. Verify FrankenLibC is built
3. Run emerge with LD_PRELOAD
4. Validate build success
5. Check log format
6. Analyze healing actions

**Environment Variables:**
- `TEST_PACKAGE`: Package to build (default: `sys-apps/which`)

### Build Wave Execution (`test_build_wave.sh`)

Tests parallel build of independent packages:
1. Build 3 packages in parallel
2. Check for resource conflicts
3. Validate results collection

### Test Suite Execution (`test_test_suite.sh`)

Tests baseline vs instrumented comparison:
1. Run tests without FrankenLibC (baseline)
2. Run tests with FrankenLibC (instrumented)
3. Compare results and calculate verdict
4. Analyze healing actions during tests

**Environment Variables:**
- `TEST_PACKAGE`: Package to test (default: `app-arch/gzip`)

### Full Pipeline (`test_full_pipeline.sh`)

Tests complete pipeline with 5 packages:
1. Build all packages
2. Run tests for built packages
3. Generate analysis report
4. Validate all artifacts

### Failure Recovery (`test_failure_recovery.sh`)

Tests behavior when things go wrong:
1. Simulate build failure
2. Verify failure categorization
3. Check logs preserved
4. Verify resume state handling

### Progress Reporting (`test_progress_reporting.sh`)

Tests progress output during long runs:
1. Track progress events
2. Verify ETA calculation
3. Validate JSON output format
4. Generate webhook payload

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FRANKENLIBC_IMAGE` | Docker image to use | `frankenlibc/gentoo-frankenlibc:latest` |
| `FRANKENLIBC_MODE` | FrankenLibC mode | `hardened` |
| `E2E_TIMEOUT` | Build timeout (seconds) | `1800` |
| `E2E_ARTIFACTS` | Artifact directory | `/tmp/frankenlibc-e2e` |

### Example

```bash
# Use a different image and mode
FRANKENLIBC_IMAGE=my-image:latest \
FRANKENLIBC_MODE=strict \
./run_all_e2e.sh single_package
```

## Output

### Log Files

Each test creates a timestamped result directory under `$E2E_ARTIFACTS`:

```
/tmp/frankenlibc-e2e/
├── single-package-build-20260213-012345/
│   ├── test.log           # Test execution log
│   ├── summary.json       # Test summary
│   └── package/
│       ├── build.log      # Package build output
│       └── frankenlibc.jsonl  # Healing actions
└── e2e_summary.json       # Overall summary
```

### Log Format

All tests use a consistent log format:

```
2026-02-13T01:45:00Z [INFO] === E2E Test: Single Package Build ===
2026-02-13T01:45:00Z [INFO] [Step 1/6] Checking Docker availability...
2026-02-13T01:45:00Z [OK] Docker is available
...
2026-02-13T01:50:00Z [INFO] === E2E Test PASSED ===
```

## CI Integration

### GitHub Actions

```yaml
name: E2E Tests

on:
  schedule:
    - cron: '0 2 * * *'  # Nightly
  workflow_dispatch:

jobs:
  e2e-fast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run fast E2E tests
        run: ./tests/gentoo/e2e/run_all_e2e.sh --fast
      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-results
          path: /tmp/frankenlibc-e2e/
```

## Adding New Tests

1. Create a new script in `tests/gentoo/e2e/test_<name>.sh`
2. Source `lib/common.sh` for helper functions
3. Use `e2e_init "<name>" <step_count>` to initialize
4. Use `log_step`, `log_info`, `log_success`, `log_error` for logging
5. Use `e2e_finish "pass"` or `e2e_finish "fail"` to complete
6. Add the test to `run_all_e2e.sh`

### Example

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

main() {
    e2e_init "my-test" 3

    log_step "First step..."
    # Do something
    log_success "Step completed"

    log_step "Second step..."
    # Do something else

    log_step "Third step..."
    # Final step

    e2e_finish "pass"
}

[[ "${BASH_SOURCE[0]}" == "$0" ]] && main "$@"
```

## Troubleshooting

### Docker not available

Ensure Docker is installed and running:
```bash
docker info
```

### Build timeouts

Increase the timeout:
```bash
E2E_TIMEOUT=3600 ./run_all_e2e.sh single_package
```

### Disk space issues

Clean up old artifacts:
```bash
rm -rf /tmp/frankenlibc-e2e/*
```

### Image not found

Build the image manually:
```bash
./scripts/gentoo/build-base-image.sh
docker build -f docker/gentoo/Dockerfile.frankenlibc -t frankenlibc/gentoo-frankenlibc:latest .
```
