#!/usr/bin/env bash
# CI quality gates for glibc_rust.
set -euo pipefail

echo "=== glibc_rust CI ==="
echo ""

echo "--- cargo fmt --check ---"
cargo fmt --check
echo "PASS"
echo ""

echo "--- cargo check --all-targets ---"
cargo check --all-targets
echo "PASS"
echo ""

echo "--- cargo clippy --all-targets -- -D warnings ---"
cargo clippy --all-targets -- -D warnings
echo "PASS"
echo ""

echo "--- cargo test --all-targets ---"
cargo test --all-targets
echo "PASS"
echo ""

echo "--- module inventory drift check ---"
scripts/check_module_inventory.sh
echo "PASS"
echo ""

echo "--- module wiring checklist ---"
scripts/check_module_wiring.sh || echo "WARN: wiring gaps found (non-blocking)"
echo ""

echo "--- snapshot+test coverage matrix ---"
scripts/check_snapshot_coverage.sh
echo "PASS"
echo ""

echo "--- snapshot gate (runtime_math golden) ---"
scripts/snapshot_gate.sh
echo "PASS"
echo ""

echo "--- perf gate (runtime_math + membrane) ---"
scripts/perf_gate.sh
echo "PASS"
echo ""

echo "--- CVE Arena regression gate ---"
if [ -f scripts/cve_arena_gate.sh ]; then
    scripts/cve_arena_gate.sh
    echo "PASS"
else
    echo "SKIP (cve_arena_gate.sh not found)"
fi
echo ""

echo "=== All gates passed ==="
