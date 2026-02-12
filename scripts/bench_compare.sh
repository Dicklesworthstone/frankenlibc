#!/usr/bin/env bash
# Run benchmarks and compare against baseline.
set -euo pipefail

BASELINE_DIR="${1:-target/criterion-baseline}"

echo "=== Running benchmarks ==="

if [ -d "${BASELINE_DIR}" ]; then
    echo "Comparing against baseline in ${BASELINE_DIR}"
    cargo bench -p frankenlibc-bench -- --baseline "${BASELINE_DIR}"
else
    echo "No baseline found. Running fresh benchmarks."
    cargo bench -p frankenlibc-bench -- --save-baseline "${BASELINE_DIR}"
fi
