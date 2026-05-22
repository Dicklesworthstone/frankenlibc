#!/usr/bin/env bash
# check_runtime_math_killswitch_e2e.sh — E2E test for runtime-math kill-switch (bd-06bxm.9)
#
# Verifies that:
# 1. FRANKENLIBC_RUNTIME_MATH=off disables runtime-math kernel consultation
# 2. Basic membrane validation still runs when math is disabled
# 3. FRANKENLIBC_RUNTIME_MATH=on (or absent) enables runtime-math
# 4. Invalid values fall back to on
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/runtime_math_killswitch_e2e"
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

echo "=== Runtime-Math Kill-Switch E2E Test (bd-06bxm.9) ==="
echo "Library: ${LIB_PATH}"
echo ""

# Create C fixture to test kill-switch
FIXTURE_SRC="${OUT_DIR}/fixture_killswitch.c"
FIXTURE_BIN="${OUT_DIR}/fixture_killswitch"

cat > "${FIXTURE_SRC}" <<'ENDC'
/* fixture_killswitch.c — verify FRANKENLIBC_RUNTIME_MATH kill-switch */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));
extern int __frankenlibc_is_runtime_math_enabled(void) __attribute__((weak));
extern uint64_t __frankenlibc_decision_count(void) __attribute__((weak));

int main(int argc, char** argv) {
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_math_enabled) {
        fprintf(stderr, "FAIL: FFI symbols not resolved\n");
        return 2;
    }

    int ready = __frankenlibc_is_runtime_ready();
    int math_enabled = __frankenlibc_is_runtime_math_enabled();
    uint64_t decisions = __frankenlibc_decision_count();

    /* Exercise some operations */
    void* p = malloc(64);
    if (p) free(p);

    uint64_t decisions_after = __frankenlibc_decision_count();

    printf("ready=%d math_enabled=%d decisions_before=%lu decisions_after=%lu\n",
           ready, math_enabled, decisions, decisions_after);

    /* When math is off, decisions should still be counted for basic validation */
    /* But the runtime-math kernel is not consulted */

    return math_enabled;  /* Return 1 if enabled, 0 if disabled */
}
ENDC

echo "--- Compiling fixture ---"
if ! gcc -O2 -o "${FIXTURE_BIN}" "${FIXTURE_SRC}"; then
  echo "FAIL: compilation failed"
  exit 1
fi
echo "Compiled: ${FIXTURE_BIN}"
echo ""

# Test 1: Kill-switch OFF - runtime-math should be disabled
echo "--- Test 1: FRANKENLIBC_RUNTIME_MATH=off ---"
output=$(FRANKENLIBC_RUNTIME_MATH=off FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
# rc=0 means math_enabled=0 (disabled), which is what we want
if [[ ${rc} -eq 0 ]]; then
  echo "PASS: runtime-math disabled when FRANKENLIBC_RUNTIME_MATH=off"
else
  echo "FAIL: runtime-math should be disabled when FRANKENLIBC_RUNTIME_MATH=off (got rc=${rc})"
  exit 1
fi
echo ""

# Test 2: Kill-switch ON - runtime-math should be enabled
echo "--- Test 2: FRANKENLIBC_RUNTIME_MATH=on ---"
output=$(FRANKENLIBC_RUNTIME_MATH=on FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -eq 1 ]]; then
  echo "PASS: runtime-math enabled when FRANKENLIBC_RUNTIME_MATH=on"
else
  echo "FAIL: runtime-math should be enabled when FRANKENLIBC_RUNTIME_MATH=on"
  exit 1
fi
echo ""

# Test 3: Kill-switch absent (default ON)
echo "--- Test 3: FRANKENLIBC_RUNTIME_MATH absent (default) ---"
output=$(FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -eq 1 ]]; then
  echo "PASS: runtime-math enabled by default"
else
  echo "FAIL: runtime-math should be enabled by default"
  exit 1
fi
echo ""

# Test 4: Invalid value falls back to ON
echo "--- Test 4: FRANKENLIBC_RUNTIME_MATH=invalid ---"
output=$(FRANKENLIBC_RUNTIME_MATH=invalid FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -eq 1 ]]; then
  echo "PASS: invalid value falls back to runtime-math enabled"
else
  echo "FAIL: invalid value should fall back to runtime-math enabled"
  exit 1
fi
echo ""

# Test 5: Membrane validation still runs when math is disabled
echo "--- Test 5: Basic membrane validation with math disabled ---"
output=$(FRANKENLIBC_RUNTIME_MATH=off FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 sh -c 'ls /tmp > /dev/null' 2>&1)
rc=$?
if [[ ${rc} -eq 0 ]]; then
  echo "PASS: basic operations work with runtime-math disabled"
else
  echo "FAIL: basic operations should work with runtime-math disabled"
  exit 1
fi
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/runtime_math_killswitch_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "runtime_math_killswitch_e2e.v1",
  "bead_id": "bd-06bxm.9",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "fixture_bin": "${FIXTURE_BIN}",
  "tests": {
    "off_disables_math": "pass",
    "on_enables_math": "pass",
    "default_enables_math": "pass",
    "invalid_falls_back_to_on": "pass",
    "membrane_validation_with_math_off": "pass"
  },
  "contract": {
    "env_var": "FRANKENLIBC_RUNTIME_MATH",
    "values": ["on (default)", "off"],
    "behavior": {
      "off": "Skip runtime-math kernel consultation; basic membrane validation still runs",
      "on": "Full runtime-math kernel consultation (default)",
      "invalid": "Log warning and fall back to on"
    },
    "immutability": "Resolved once at init, immutable after"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: Runtime-math kill-switch verified"
exit 0
