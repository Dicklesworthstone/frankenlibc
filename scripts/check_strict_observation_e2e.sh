#!/usr/bin/env bash
# check_strict_observation_e2e.sh — E2E test for strict-mode observation policy (bd-06bxm.3)
#
# Verifies that strict mode:
# 1. Emits evidence records (decision count increases)
# 2. Performs no behavior rewrite (returns passthrough/Allow)
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/strict_observation_e2e"
mkdir -p "${OUT_DIR}"

LIB_CANDIDATES=(
  "${FRANKENLIBC_SMOKE_LIB_PATH:-}"
  "${REPO_ROOT}/target/release/libfrankenlibc_abi.so"
  "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -n "${candidate}" && -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" ]]; then
  echo "Building libfrankenlibc_abi.so..."
  cargo build -p frankenlibc-abi --release 2>&1 | tail -3
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "FAIL: could not locate or build libfrankenlibc_abi.so" >&2
  exit 1
fi

echo "=== Strict-Mode Observation Policy E2E Test (bd-06bxm.3) ==="
echo "Library: ${LIB_PATH}"
echo ""

# Test 1: Verify strict mode emits evidence (decision count > 0)
echo "--- Test 1: Strict mode emits evidence records ---"
# Use the observe_feedback fixture which exercises IO operations
output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" timeout 10 "${REPO_ROOT}/target/observe_feedback_e2e/fixture_observe_feedback" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: fixture exited ${rc}"
  exit 1
fi
# Check that decisions were counted
decisions_after=$(echo "${output}" | grep -oP 'decisions_after=\K[0-9]+')
if [[ -z "${decisions_after}" || "${decisions_after}" -eq 0 ]]; then
  echo "FAIL: strict mode did not emit evidence (decisions_after=${decisions_after:-0})"
  exit 1
fi
echo "PASS: strict mode emitted ${decisions_after} decisions"
echo ""

# Test 2: Verify strict mode is ABI-faithful (read/write/exec work normally)
echo "--- Test 2: Strict mode is ABI-faithful (no rewrites) ---"
# Create a simple test file
test_file="${OUT_DIR}/test_abi_faithful.txt"
echo "test content" > "${test_file}"

# Test read
read_output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" cat "${test_file}" 2>&1)
if [[ "${read_output}" != "test content" ]]; then
  echo "FAIL: read content mismatch: got '${read_output}'"
  exit 1
fi
echo "PASS: read is ABI-faithful"

# Test write
FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" sh -c "echo 'written content' > '${test_file}'"
written_content=$(cat "${test_file}")
if [[ "${written_content}" != "written content" ]]; then
  echo "FAIL: write content mismatch: got '${written_content}'"
  exit 1
fi
echo "PASS: write is ABI-faithful"

# Test exec with complex command
ls_output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" ls -la /etc/hosts 2>&1)
if ! echo "${ls_output}" | grep -q "hosts"; then
  echo "FAIL: exec output unexpected: ${ls_output}"
  exit 1
fi
echo "PASS: exec is ABI-faithful"
echo ""

# Test 3: Verify python3 works correctly in strict mode
echo "--- Test 3: Python3 runs correctly in strict mode ---"
python_output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" python3 -c "print(2+2)" 2>&1)
if [[ "${python_output}" != "4" ]]; then
  echo "FAIL: python3 output unexpected: '${python_output}'"
  exit 1
fi
echo "PASS: python3 works in strict mode"
echo ""

# Cleanup
rm -f "${test_file}"

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/strict_observation_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "strict_observation_e2e.v1",
  "bead_id": "bd-06bxm.3",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "tests": {
    "evidence_emitted": "pass",
    "read_abi_faithful": "pass",
    "write_abi_faithful": "pass",
    "exec_abi_faithful": "pass",
    "python3_works": "pass"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: Strict mode observation policy verified"
exit 0
