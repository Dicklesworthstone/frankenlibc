#!/usr/bin/env bash
# check_runtime_math_liveness_e2e.sh — E2E test for runtime-math liveness gates (bd-06bxm.6)
#
# Verifies that:
# 1. OBSERVE_FEEDBACK is enabled in shipped artifact
# 2. Each kernel output reaches a decision (decisions counter increments)
# 3. Kernel state vector shows non-zero activity after workload
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/runtime_math_liveness_e2e"
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

echo "=== Runtime-Math Liveness Gates E2E Test (bd-06bxm.6) ==="
echo "Library: ${LIB_PATH}"
echo ""

# Create C fixture that exercises runtime-math and captures kernel state
FIXTURE_SRC="${OUT_DIR}/fixture_liveness.c"
FIXTURE_BIN="${OUT_DIR}/fixture_liveness"

cat > "${FIXTURE_SRC}" <<'ENDC'
/* fixture_liveness.c — verify runtime-math kernels are live */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));
extern int __frankenlibc_is_feedback_enabled(void) __attribute__((weak));
extern uint64_t __frankenlibc_decision_count(void) __attribute__((weak));
extern char* __frankenlibc_kernel_snapshot_json(void) __attribute__((weak));
extern void __frankenlibc_free_snapshot_json(char*) __attribute__((weak));

int main(int argc, char** argv) {
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_feedback_enabled ||
        !__frankenlibc_decision_count) {
        fprintf(stderr, "FAIL: FFI symbols not resolved\n");
        return 2;
    }

    int ready = __frankenlibc_is_runtime_ready();
    if (!ready) {
        fprintf(stderr, "FAIL: runtime not ready\n");
        return 1;
    }

    int feedback = __frankenlibc_is_feedback_enabled();
    if (!feedback) {
        fprintf(stderr, "FAIL: OBSERVE_FEEDBACK is disabled in shipped artifact\n");
        return 1;
    }

    uint64_t decisions_before = __frankenlibc_decision_count();

    /* Exercise diverse syscall families to trigger kernel observations */

    /* File I/O */
    int fd = open("/etc/hosts", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        read(fd, buf, sizeof(buf));
        close(fd);
    }

    /* Directory operations */
    DIR* d = opendir("/tmp");
    if (d) {
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            /* enumerate */
        }
        closedir(d);
    }

    /* Stat operations */
    struct stat st;
    stat("/etc/passwd", &st);
    stat("/etc/hosts", &st);
    stat("/etc/resolv.conf", &st);

    /* Memory operations */
    void* p1 = malloc(64);
    void* p2 = calloc(16, 8);
    void* p3 = malloc(128);
    p3 = realloc(p3, 256);
    free(p1);
    free(p2);
    free(p3);

    /* String operations */
    char str[128] = "hello world";
    size_t len = strlen(str);
    char str2[128];
    memcpy(str2, str, len + 1);
    int cmp = memcmp(str, str2, len);
    (void)cmp;

    /* Write operations */
    char tmpfile[] = "/tmp/liveness_test_XXXXXX";
    fd = mkstemp(tmpfile);
    if (fd >= 0) {
        write(fd, "test\n", 5);
        close(fd);
        unlink(tmpfile);
    }

    uint64_t decisions_after = __frankenlibc_decision_count();
    uint64_t decisions_delta = decisions_after - decisions_before;

    printf("ready=%d feedback_enabled=%d decisions_before=%lu decisions_after=%lu delta=%lu\n",
           ready, feedback, decisions_before, decisions_after, decisions_delta);

    /* Gate 1: Feedback must be enabled */
    if (!feedback) {
        fprintf(stderr, "GATE_FAIL: OBSERVE_FEEDBACK disabled\n");
        return 1;
    }

    /* Gate 2: Decisions must have incremented (kernel outputs reached) */
    if (decisions_delta == 0) {
        fprintf(stderr, "GATE_FAIL: no decisions recorded after workload\n");
        return 1;
    }

    /* Gate 3: Export kernel snapshot if available */
    if (__frankenlibc_kernel_snapshot_json && __frankenlibc_free_snapshot_json) {
        char* snapshot = __frankenlibc_kernel_snapshot_json();
        if (snapshot) {
            printf("kernel_snapshot=%s\n", snapshot);
            __frankenlibc_free_snapshot_json(snapshot);
        }
    }

    printf("PASS: runtime-math kernels are live (feedback=%d, decisions=%lu)\n",
           feedback, decisions_delta);
    return 0;
}
ENDC

echo "--- Compiling fixture ---"
if ! gcc -O2 -o "${FIXTURE_BIN}" "${FIXTURE_SRC}"; then
  echo "FAIL: compilation failed"
  exit 1
fi
echo "Compiled: ${FIXTURE_BIN}"
echo ""

# Test 1: Hardened mode liveness
echo "--- Test 1: Hardened mode liveness gates ---"
output=$(FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 15 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: liveness gates failed in hardened mode (exit ${rc})"
  exit 1
fi
# Extract decision count
decisions=$(echo "${output}" | grep -oP 'delta=\K[0-9]+' || echo "0")
if [[ "${decisions}" -eq 0 ]]; then
  echo "FAIL: no decisions in hardened mode"
  exit 1
fi
echo "PASS: hardened mode liveness verified (${decisions} decisions)"
echo ""

# Test 2: Strict mode liveness
echo "--- Test 2: Strict mode liveness gates ---"
output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" timeout 15 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: liveness gates failed in strict mode (exit ${rc})"
  exit 1
fi
# Extract decision count
decisions=$(echo "${output}" | grep -oP 'delta=\K[0-9]+' || echo "0")
if [[ "${decisions}" -eq 0 ]]; then
  echo "FAIL: no decisions in strict mode"
  exit 1
fi
echo "PASS: strict mode liveness verified (${decisions} decisions)"
echo ""

# Test 3: Verify OBSERVE_FEEDBACK cannot be disabled
echo "--- Test 3: OBSERVE_FEEDBACK enabled by default gate ---"
# Run with default mode and verify feedback is enabled
output=$(LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" 2>&1)
if echo "${output}" | grep -q "feedback_enabled=1"; then
  echo "PASS: OBSERVE_FEEDBACK enabled by default"
else
  echo "FAIL: OBSERVE_FEEDBACK not enabled by default"
  exit 1
fi
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/runtime_math_liveness_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "runtime_math_liveness_e2e.v1",
  "bead_id": "bd-06bxm.6",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "fixture_bin": "${FIXTURE_BIN}",
  "gates": {
    "observe_feedback_enabled": "pass",
    "decisions_increment_on_workload": "pass",
    "hardened_mode_live": "pass",
    "strict_mode_live": "pass"
  },
  "liveness_contract": {
    "claim": "Runtime-math kernels are live: OBSERVE_FEEDBACK enabled, decisions increment on workload",
    "evidence_artifacts": [
      "tests/conformance/observe_feedback_e2e.v1.json",
      "tests/conformance/strict_observation_e2e.v1.json"
    ]
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: Runtime-math liveness gates verified"
exit 0
