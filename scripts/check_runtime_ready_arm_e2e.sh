#!/usr/bin/env bash
# check_runtime_ready_arm_e2e.sh — E2E test for RUNTIME_READY arming under LD_PRELOAD (bd-06bxm.1)
#
# Verifies that signal_runtime_ready() is called in the startup path and the
# runtime-math kernel arms without deadlock, even with constructor-heavy binaries.
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/runtime_ready_arm_e2e"
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

FIXTURE_SRC="${REPO_ROOT}/tests/integration/fixture_runtime_ready_arm.cpp"
FIXTURE_BIN="${OUT_DIR}/fixture_runtime_ready_arm"

echo "=== RUNTIME_READY Arming E2E Test (bd-06bxm.1) ==="
echo "Library: ${LIB_PATH}"
echo ""

# Compile the C++ fixture
echo "--- Compiling fixture ---"
if ! g++ -O2 -o "${FIXTURE_BIN}" "${FIXTURE_SRC}"; then
  echo "FAIL: compilation failed"
  exit 1
fi
echo "Compiled: ${FIXTURE_BIN}"
echo ""

# Test 1: Run without LD_PRELOAD (should exit 2 - FFI symbols not resolved)
echo "--- Test 1: Without LD_PRELOAD (expect FFI not resolved) ---"
if "${FIXTURE_BIN}" 2>&1; then
  echo "FAIL: fixture should fail without LD_PRELOAD"
  exit 1
fi
echo "PASS: correctly fails without LD_PRELOAD"
echo ""

# Test 2: Run with LD_PRELOAD in strict mode
echo "--- Test 2: Strict mode LD_PRELOAD ---"
output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" -v 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: fixture exited ${rc} in strict mode"
  exit 1
fi
echo "PASS: strict mode runtime armed"
echo ""

# Test 3: Run with LD_PRELOAD in hardened mode
echo "--- Test 3: Hardened mode LD_PRELOAD ---"
output=$(FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" -v 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: fixture exited ${rc} in hardened mode"
  exit 1
fi
echo "PASS: hardened mode runtime armed"
echo ""

# Test 4: Run multiple times in parallel to stress test arming
echo "--- Test 4: Parallel stress test (8 concurrent) ---"
pids=()
for i in {1..8}; do
  (FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" timeout 5 "${FIXTURE_BIN}" >/dev/null 2>&1) &
  pids+=($!)
done

failed=0
for pid in "${pids[@]}"; do
  wait "${pid}" || ((failed++))
done

if [[ ${failed} -gt 0 ]]; then
  echo "FAIL: ${failed}/8 parallel runs failed"
  exit 1
fi
echo "PASS: all 8 parallel runs succeeded"
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/runtime_ready_arm_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "runtime_ready_arm_e2e.v1",
  "bead_id": "bd-06bxm.1",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "fixture_bin": "${FIXTURE_BIN}",
  "tests": {
    "no_preload_fails": "pass",
    "strict_mode_arms": "pass",
    "hardened_mode_arms": "pass",
    "parallel_stress": "pass"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: All RUNTIME_READY arming tests passed"
exit 0
