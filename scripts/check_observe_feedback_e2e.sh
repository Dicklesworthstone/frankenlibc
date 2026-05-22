#!/usr/bin/env bash
# check_observe_feedback_e2e.sh — E2E test for OBSERVE_FEEDBACK enabled by default (bd-06bxm.2)
#
# Verifies that validation feedback is enabled and exotic kernel state receives
# live observations after a representative workload.
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/observe_feedback_e2e"
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

echo "=== OBSERVE_FEEDBACK E2E Test (bd-06bxm.2) ==="
echo "Library: ${LIB_PATH}"
echo ""

# Create a C test program that exercises FFI exports
FIXTURE_SRC="${OUT_DIR}/fixture_observe_feedback.c"
FIXTURE_BIN="${OUT_DIR}/fixture_observe_feedback"

cat > "${FIXTURE_SRC}" <<'ENDC'
/* fixture_observe_feedback.c — verify feedback is enabled and decisions are counted */
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

int main(int argc, char** argv) {
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_feedback_enabled || !__frankenlibc_decision_count) {
        fprintf(stderr, "FAIL: FFI symbols not resolved\n");
        return 2;
    }

    int ready = __frankenlibc_is_runtime_ready();
    int feedback_enabled = __frankenlibc_is_feedback_enabled();
    uint64_t decisions_before = __frankenlibc_decision_count();

    /* Exercise IO operations which DO go through decide() in hardened mode.
     * Note: Allocator/StringMemory families use fast paths and skip decide(). */

    /* Read /proc/self/maps - exercises read() and file operations */
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            /* process data */
        }
        close(fd);
    }

    /* Exercise directory operations */
    DIR* d = opendir("/tmp");
    if (d) {
        struct dirent* ent;
        while ((ent = readdir(d)) != NULL) {
            /* enumerate */
        }
        closedir(d);
    }

    /* Exercise stat operations */
    struct stat st;
    stat("/etc/passwd", &st);
    stat("/etc/hosts", &st);

    /* Create and remove a temp file */
    char tmpfile[] = "/tmp/frankenlibc_feedback_test_XXXXXX";
    fd = mkstemp(tmpfile);
    if (fd >= 0) {
        write(fd, "test\n", 5);
        close(fd);
        unlink(tmpfile);
    }

    uint64_t decisions_after = __frankenlibc_decision_count();

    printf("ready=%d feedback_enabled=%d decisions_before=%lu decisions_after=%lu delta=%lu\n",
           ready, feedback_enabled, decisions_before, decisions_after, decisions_after - decisions_before);

    if (!ready) {
        fprintf(stderr, "FAIL: runtime not ready\n");
        return 1;
    }
    if (!feedback_enabled) {
        fprintf(stderr, "FAIL: feedback not enabled\n");
        return 1;
    }
    /* In hardened mode, IO decisions should be counted. */
    if (argc > 1 && strcmp(argv[1], "--require-decisions") == 0) {
        if (decisions_after <= decisions_before) {
            fprintf(stderr, "FAIL: no new decisions after workload (IO ops should trigger decide())\n");
            return 1;
        }
    }

    printf("PASS\n");
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

# Test 1: Strict mode (feedback enabled but fast path skips decisions)
echo "--- Test 1: Strict mode (feedback enabled, decisions may be skipped) ---"
output=$(FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: fixture exited ${rc} in strict mode"
  exit 1
fi
echo "PASS: strict mode feedback enabled"
echo ""

# Test 2: Hardened mode (feedback enabled and decisions counted)
echo "--- Test 2: Hardened mode (feedback enabled, decisions counted) ---"
output=$(FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" timeout 10 "${FIXTURE_BIN}" --require-decisions 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: fixture exited ${rc} in hardened mode"
  exit 1
fi
echo "PASS: hardened mode feedback enabled with decisions"
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/observe_feedback_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "observe_feedback_e2e.v1",
  "bead_id": "bd-06bxm.2",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "fixture_bin": "${FIXTURE_BIN}",
  "tests": {
    "strict_mode_feedback_enabled": "pass",
    "hardened_mode_decisions_counted": "pass"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: All OBSERVE_FEEDBACK tests passed"
exit 0
