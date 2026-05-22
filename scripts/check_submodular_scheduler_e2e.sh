#!/usr/bin/env bash
# check_submodular_scheduler_e2e.sh — E2E test for submodular-knapsack monitor scheduler (bd-06bxm.4)
#
# Verifies that:
# 1. Per-call monitor count is bounded by budget
# 2. The design controller's greedy selection works correctly
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Submodular-Knapsack Monitor Scheduler E2E Test (bd-06bxm.4) ==="
echo ""

# Run the specific unit tests
echo "--- Running per_call_monitor test ---"
output=$(cargo test --package frankenlibc-membrane --lib per_call_monitor -- --test-threads=1 2>&1)
if ! echo "${output}" | grep -q "1 passed"; then
  echo "${output}"
  echo "FAIL: per_call_monitor test did not pass"
  exit 1
fi
echo "PASS: per_call_monitor_count_bounded_by_budget test passed"
echo ""

echo "--- Running greedy_selection test ---"
output=$(cargo test --package frankenlibc-membrane --lib greedy_selection -- --test-threads=1 2>&1)
if ! echo "${output}" | grep -q "1 passed"; then
  echo "${output}"
  echo "FAIL: greedy_selection test did not pass"
  exit 1
fi
echo "PASS: greedy_selection_achieves_submodular_optimality_bound test passed"
echo ""

# Verify the design module compiles with expected interface
echo "--- Verifying design module interface ---"
output=$(cargo test --package frankenlibc-membrane --lib design::tests -- --test-threads=1 2>&1)
if ! echo "${output}" | grep -q "9 passed"; then
  echo "${output}"
  echo "FAIL: design module tests did not all pass"
  exit 1
fi
echo "PASS: All 9 design module tests passed"
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/submodular_scheduler_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "submodular_scheduler_e2e.v1",
  "bead_id": "bd-06bxm.4",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tests": {
    "per_call_monitor_count_bounded": "pass",
    "greedy_selection_submodular_bound": "pass",
    "design_module_tests": "pass (9/9)"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: Submodular-knapsack scheduler verified"
exit 0
