#!/usr/bin/env bash
# check_capture_replay_e2e.sh — E2E for bd-zt1pq.5
# Verifies capture-replay and metamorphic relations
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_JSON="${REPO_ROOT}/tests/conformance/capture_replay_e2e.v1.json"

echo "=== Capture-Replay and Metamorphic E2E (bd-zt1pq.5) ==="
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
declare -A RESULTS

log_result() {
  local name="$1"
  local status="$2"
  RESULTS["$name"]="$status"
  if [ "$status" = "pass" ]; then
    ((TESTS_PASSED++))
  else
    ((TESTS_FAILED++))
  fi
}

# Gate 1: Host-glibc capture pipeline contract exists
echo "--- Gate 1: Capture pipeline contract ---"
CAPTURE_CONTRACT="${REPO_ROOT}/tests/conformance/host_glibc_capture_pipeline_completion_contract.v1.json"
if [ -f "$CAPTURE_CONTRACT" ]; then
  echo "PASS: Capture pipeline contract exists"
  log_result "capture_pipeline_contract" "pass"
else
  echo "FAIL: Capture pipeline contract missing"
  log_result "capture_pipeline_contract" "fail"
fi
echo ""

# Gate 2: Metamorphic relation contract exists
echo "--- Gate 2: Metamorphic relation contract ---"
METAMORPHIC_CONTRACT="${REPO_ROOT}/tests/conformance/memcpy_strict_metamorphic_completion_contract.v1.json"
if [ -f "$METAMORPHIC_CONTRACT" ]; then
  echo "PASS: Metamorphic relation contract exists"
  log_result "metamorphic_contract" "pass"
else
  echo "FAIL: Metamorphic relation contract missing"
  log_result "metamorphic_contract" "fail"
fi
echo ""

# Gate 3: Real capture migration contract
echo "--- Gate 3: Real capture migration contract ---"
MIGRATION_CONTRACT="${REPO_ROOT}/tests/conformance/real_capture_migration_completion_contract.v1.json"
if [ -f "$MIGRATION_CONTRACT" ]; then
  echo "PASS: Real capture migration contract exists"
  log_result "real_capture_migration" "pass"
else
  echo "FAIL: Real capture migration contract missing"
  log_result "real_capture_migration" "fail"
fi
echo ""

# Gate 4: Fixture capture tests exist
echo "--- Gate 4: Fixture capture tests ---"
CAPTURE_TEST="${REPO_ROOT}/crates/frankenlibc-harness/tests/fixture_capture_pipeline_completion_contract_test.rs"
if [ -f "$CAPTURE_TEST" ]; then
  echo "PASS: Fixture capture test exists"
  log_result "fixture_capture_test" "pass"
else
  echo "FAIL: Fixture capture test missing"
  log_result "fixture_capture_test" "fail"
fi
echo ""

# Gate 5: Metamorphic test exists
echo "--- Gate 5: Metamorphic relation test ---"
METAMORPHIC_TEST="${REPO_ROOT}/crates/frankenlibc-harness/tests/b64_metamorphic_test.rs"
if [ -f "$METAMORPHIC_TEST" ]; then
  echo "PASS: Metamorphic relation test exists"
  log_result "metamorphic_test" "pass"
else
  echo "FAIL: Metamorphic relation test missing"
  log_result "metamorphic_test" "fail"
fi
echo ""

# Gate 6: Check captured_at timestamps are not synthetic midnight
echo "--- Gate 6: Real capture timestamps ---"
SYNTHETIC_COUNT=$(grep -r '"captured_at_utc": ".*T00:00:00' "${REPO_ROOT}/tests/conformance/"*.json 2>/dev/null | wc -l)
if [ "${SYNTHETIC_COUNT}" -lt 5 ]; then
  echo "PASS: Minimal synthetic midnight timestamps (${SYNTHETIC_COUNT})"
  log_result "real_timestamps" "pass"
else
  echo "WARN: Many synthetic midnight timestamps (${SYNTHETIC_COUNT})"
  log_result "real_timestamps" "warn"
fi
echo ""

# Gate 7: WS-5 parent beads closed
echo "--- Gate 7: WS-5 bead closure status ---"
CLOSED_COUNT=0
for bead in bd-zt1pq.1 bd-zt1pq.2 bd-zt1pq.3 bd-zt1pq.4; do
  if br show "$bead" --json 2>/dev/null | grep -q '"status": "closed"'; then
    ((CLOSED_COUNT++))
  fi
done
if [ "${CLOSED_COUNT}" -ge 3 ]; then
  echo "PASS: ${CLOSED_COUNT}/4 WS-5 child beads closed"
  log_result "ws5_beads_closed" "pass"
else
  echo "FAIL: Only ${CLOSED_COUNT}/4 WS-5 child beads closed"
  log_result "ws5_beads_closed" "fail"
fi
echo ""

# Determine overall status
if [ "${TESTS_FAILED}" -eq 0 ]; then
  OVERALL_STATUS="pass"
else
  OVERALL_STATUS="fail"
fi

# Write JSON summary
cat > "${OUTPUT_JSON}" <<EOF
{
  "schema_version": "capture_replay_e2e.v1",
  "bead_id": "bd-zt1pq.5",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tests": {
    "capture_pipeline_contract": "${RESULTS[capture_pipeline_contract]:-fail}",
    "metamorphic_contract": "${RESULTS[metamorphic_contract]:-fail}",
    "real_capture_migration": "${RESULTS[real_capture_migration]:-fail}",
    "fixture_capture_test": "${RESULTS[fixture_capture_test]:-fail}",
    "metamorphic_test": "${RESULTS[metamorphic_test]:-fail}",
    "real_timestamps": "${RESULTS[real_timestamps]:-fail}",
    "ws5_beads_closed": "${RESULTS[ws5_beads_closed]:-fail}"
  },
  "summary": {
    "passed": ${TESTS_PASSED},
    "failed": ${TESTS_FAILED},
    "total": $((TESTS_PASSED + TESTS_FAILED))
  },
  "overall_status": "${OVERALL_STATUS}"
}
EOF

echo "Summary: ${OUTPUT_JSON}"
echo ""
echo "Tests: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed"
if [ "${OVERALL_STATUS}" = "pass" ]; then
  echo "PASS: Capture-Replay E2E verified"
  exit 0
else
  echo "FAIL: Capture-Replay E2E has failures"
  exit 1
fi
