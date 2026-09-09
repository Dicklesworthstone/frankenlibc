#!/usr/bin/env bash
# check_runtime_math_killswitch_e2e.sh — E2E test for runtime-math kill-switch (bd-06bxm.9)
#
# Verifies that:
# 1. FRANKENLIBC_RUNTIME_MATH=off disables runtime-math kernel consultation
# 2. Basic operations still run when math is disabled (not a bounds-check proof)
# 3. FRANKENLIBC_RUNTIME_MATH=on (or absent) enables runtime-math
# 4. Invalid values fall back to on
# --policy-history runs matched 512-call histories and reports decisions; it
# checks consultation and liveness, not whether action/profile influence exists.
# --bounds-repair checks source-bound clamping with math off and on in hardened
# mode. It never runs the intentionally oversized copy against strict libc.
# --thread-signal exercises concurrent sockets and writes from a signal handler;
# delivery is between socket calls, not proof of interruption inside a lock.
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

if [[ -z "${LIB_PATH}" && "${1:-}" != "--compile-fixture" ]]; then
  echo "Building libfrankenlibc_abi.so..."
  RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -Z checksum-freshness -p frankenlibc-abi --release || exit $?
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -n "${candidate}" && -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" && "${1:-}" != "--compile-fixture" ]]; then
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
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));
extern int __frankenlibc_is_runtime_math_enabled(void) __attribute__((weak));
extern uint64_t __frankenlibc_decision_count(void) __attribute__((weak));
extern uint64_t __frankenlibc_healing_action_count(unsigned) __attribute__((weak));

static int signal_pipe[2];
static int constructor_result = -1;
static int constructor_ready = -1;
static int constructor_calls;

__attribute__((constructor)) static void probe_constructor(void) {
    ++constructor_calls;
    const char *enabled = getenv("FRANKENLIBC_PROBE_CONSTRUCTOR");
    if (!enabled || enabled[0] != '1') return;
    if (__frankenlibc_is_runtime_ready) constructor_ready = __frankenlibc_is_runtime_ready();
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    constructor_result = fd >= 0 && close(fd) == 0;
}

static void probe_signal_handler(int signum) {
    (void)signum;
    int saved_errno = errno;
    /* Only an async-signal-safe operation in the handler. Four workers emit
     * 64 bytes each, below the pipe capacity; failures are detected by count. */
    if (write(signal_pipe[1], "S", 1) != 1) _exit(3);
    errno = saved_errno;
}

static void *probe_thread(void *unused) {
    (void)unused;
    for (int i = 0; i < 64; ++i) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0 || close(fd) != 0 || raise(SIGUSR1) != 0) return (void*)1;
    }
    return NULL;
}

static int thread_signal_probe(void) {
    if (constructor_calls != 1 || constructor_result != 1) {
        fprintf(stderr, "FAIL: constructor socket probe did not succeed (calls=%d result=%d ready=%d)\n",
                constructor_calls, constructor_result, constructor_ready);
        return 2;
    }
    if (pipe(signal_pipe) != 0) return 2;
    struct sigaction action = {0};
    action.sa_handler = probe_signal_handler;
    if (sigemptyset(&action.sa_mask) != 0 || sigaction(SIGUSR1, &action, NULL) != 0) return 2;
    pthread_t threads[4];
    for (int i = 0; i < 4; ++i) if (pthread_create(&threads[i], NULL, probe_thread, NULL) != 0) return 2;
    for (int i = 0; i < 4; ++i) {
        void *result;
        if (pthread_join(threads[i], &result) != 0 || result != NULL) return 2;
    }
    if (close(signal_pipe[1]) != 0) return 2;
    unsigned char bytes[256];
    size_t total = 0;
    for (;;) {
        ssize_t count = read(signal_pipe[0], bytes, sizeof(bytes));
        if (count < 0) return 2;
        if (count == 0) break;
        for (ssize_t i = 0; i < count; ++i) if (bytes[i] != 'S') return 2;
        total += (size_t)count;
    }
    if (close(signal_pipe[0]) != 0 || total != 256) return 2;
    printf("constructor_socket=1 constructor_ready=%d threads=4 sockets=256 signal_bytes=%zu joined=4\n",
           constructor_ready, total);
    return 0;
}

static int bounds_repair(void) {
    if (!__frankenlibc_healing_action_count) return 2;
    const char *mode = getenv("FRANKENLIBC_MODE");
    if (!mode || strcmp(mode, "hardened") != 0) {
        fprintf(stderr, "FAIL: bounds fault probe requires hardened mode\n");
        return 2;
    }
    void *(*volatile copy)(void*, const void*, size_t) = memcpy;
    unsigned char *src = malloc(8), *dst = malloc(32);
    if (!src || !dst) return 2;
    for (size_t i = 0; i < 8; ++i) ((volatile unsigned char*)src)[i] = 'A' + i;
    for (size_t i = 0; i < 32; ++i) ((volatile unsigned char*)dst)[i] = 'J';

    /* Valid counterpart first; initialize through the guarded libc operation,
     * not through a diagnostic that may lazily initialize healing itself. */
    if (copy(dst, src, 8) != dst) return 2;
    for (size_t i = 0; i < 8; ++i) if (dst[i] != 'A' + i) return 2;
    for (size_t i = 0; i < 32; ++i) ((volatile unsigned char*)dst)[i] = 'J';
    uint64_t heals_before = __frankenlibc_healing_action_count(1);
    uint64_t decisions_before = __frankenlibc_decision_count();
    if (copy(dst, src, 8) != dst ||
        __frankenlibc_healing_action_count(1) != heals_before) return 2;
    for (size_t i = 0; i < 8; ++i) if (dst[i] != 'A' + i) return 2;
    for (size_t i = 8; i < 32; ++i) if (dst[i] != 'J') return 2;
    for (size_t i = 0; i < 32; ++i) ((volatile unsigned char*)dst)[i] = 'J';

    /* Deliberate source over-read request in this isolated hardened process.
     * Every inspection below stays INSIDE the allocated destination. A raw
     * copy overwrites the sentinel suffix; a no-op fails the prefix check. */
    if (copy(dst, src, 32) != dst) return 2;
    uint64_t heals_after = __frankenlibc_healing_action_count(1);
    uint64_t decisions_after = __frankenlibc_decision_count();
    for (size_t i = 0; i < 8; ++i) if (dst[i] != 'A' + i) return 2;
    for (size_t i = 8; i < 32; ++i) if (dst[i] != 'J') return 2;
    if (heals_after != heals_before + 1) return 2;
    if (!__frankenlibc_is_runtime_math_enabled() && decisions_after != decisions_before) return 2;
    printf("bounds_repair=clamp prefix=8 untouched_suffix=24 heals=%lu decisions=%lu\n",
           heals_after - heals_before, decisions_after - decisions_before);
    free(dst);
    free(src);
    return 0;
}

struct decision_snapshot {
    uint64_t evidence_seqno;
    uint32_t family, profile, action, risk_upper_bound_ppm, policy_id, reserved;
};
extern int __frankenlibc_runtime_decision_snapshot(struct decision_snapshot*) __attribute__((weak));

/* Matched process histories: identical decision contexts, differing syscall
 * outcomes. The final probe is the SAME valid socket call in both processes. */
static int policy_history(int adverse) {
    if (!__frankenlibc_runtime_decision_snapshot) {
        fprintf(stderr, "FAIL: decision snapshot export missing\n");
        return 2;
    }
    int failures = 0;
    for (int i = 0; i < 512; ++i) {
        int fd = socket(AF_UNIX, adverse ? -1 : SOCK_STREAM, 0);
        if (fd < 0) ++failures;
        else if (close(fd) != 0) return 2;
    }
    if (failures != (adverse ? 512 : 0)) {
        fprintf(stderr, "FAIL: unexpected history outcomes: %d\n", failures);
        return 2;
    }
    /* Initialize the separate counter diagnostic before the operation whose
     * thread-local record we want: its first kernel initialization can itself
     * make interposed calls, unlike this snapshot's non-initializing read. */
    uint64_t before = __frankenlibc_decision_count();
    errno = 0;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    int saved_errno = errno;
    struct decision_snapshot snapshot, repeated;
    int got = __frankenlibc_runtime_decision_snapshot(&snapshot);
    int again = __frankenlibc_runtime_decision_snapshot(&repeated);
    uint64_t after = __frankenlibc_decision_count();
    if (got != 1 || again != 1 ||
        memcmp(&snapshot, &repeated, sizeof(snapshot)) != 0 ||
        snapshot.family != 13 || snapshot.reserved != 0) {
        fprintf(stderr, "FAIL: snapshot missing, stale family, or mutating read (got=%d again=%d family=%u)\n", got, again, got == 1 ? snapshot.family : 999);
        return 2;
    }
    if (fd < 0 || saved_errno != 0) {
        fprintf(stderr, "FAIL: valid final socket changed result or errno\n");
        return 2;
    }
    if (close(fd) != 0) return 2;
    int enabled = __frankenlibc_is_runtime_math_enabled();
    if (after - before != (uint64_t)enabled) {
        fprintf(stderr, "FAIL: probe plus diagnostic reads did not produce exactly %d decision(s)\n", enabled);
        return 2;
    }
    /* Exercise comparison results too: a Deny path returning zero must not
     * masquerade as a successful equal-snapshot comparison. */
    int (*volatile compare)(const void*, const void*, size_t) = memcmp;
    const unsigned char low[] = {1, 2, 3, 4}, high[] = {1, 2, 3, 5};
    if (compare(low, high, sizeof(low)) >= 0 ||
        compare(high, low, sizeof(low)) <= 0 ||
        compare(low, high, 0) != 0) return 2;
    printf("history=%s failures=%d result=%d errno=%d sequence=%lu profile=%u action=%u risk=%u policy=%u\n",
           adverse ? "adverse" : "successful", failures, fd < 0 ? -1 : 0,
           saved_errno, snapshot.evidence_seqno, snapshot.profile, snapshot.action,
           snapshot.risk_upper_bound_ppm, snapshot.policy_id);
    /* Evidence publication is sampled every 16384 ordinary decisions. Its
     * sequence can be zero even when the exact counter delta above is one. */
    return 0;
}

int main(int argc, char** argv) {
    /* Same valid constructor/thread/signal workload against live host libc,
     * without requiring FrankenLibC-only diagnostic exports. */
    if (argc == 2 && strcmp(argv[1], "--constructor-host-control") == 0)
        return thread_signal_probe();
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_math_enabled ||
        !__frankenlibc_decision_count) {
        fprintf(stderr, "FAIL: FFI symbols not resolved\n");
        return 2;
    }

    int ready = __frankenlibc_is_runtime_ready();
    if (!ready) {
        fprintf(stderr, "FAIL: runtime is not active\n");
        return 2;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "--thread-signal") == 0) return thread_signal_probe();
        if (strcmp(argv[1], "--healing-counter-first-use") == 0) {
            if (!__frankenlibc_healing_action_count) return 2;
            uint64_t count = __frankenlibc_healing_action_count(1);
            if (__frankenlibc_healing_action_count(1) != count) return 2;
            printf("first_use_healing_counter=%lu repeated_read=stable\n", count);
            return 0;
        }
        if (strcmp(argv[1], "--bounds-repair") == 0) return bounds_repair();
        if (strcmp(argv[1], "--successful-history") == 0) return policy_history(0);
        if (strcmp(argv[1], "--adverse-history") == 0) return policy_history(1);
        return 2;
    }
    int math_enabled = __frankenlibc_is_runtime_math_enabled();
    uint64_t decisions = __frankenlibc_decision_count();

    /* Socket is not a production high-frequency passthrough family. */
    for (int i = 0; i < 16; ++i) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("FAIL: socket");
            return 2;
        }
        if (close(fd) != 0) return 2;
    }

    /* Retain the original allocation smoke. */
    void* p = malloc(64);
    if (p) free(p);

    uint64_t decisions_after = __frankenlibc_decision_count();

    printf("ready=%d math_enabled=%d decisions_before=%lu decisions_after=%lu\n",
           ready, math_enabled, decisions, decisions_after);

    /* The counter measures adaptive consultations, NOT independent bounds checks. */
    if ((!math_enabled && decisions_after != decisions) ||
        (math_enabled && decisions_after <= decisions)) {
        fprintf(stderr, "FAIL: switch state disagrees with kernel decision delta\n");
        return 2;
    }

    return math_enabled;  /* Return 1 if enabled, 0 if disabled */
}
ENDC

echo "--- Compiling fixture ---"
if [[ "${1:-}" == "--compile-fixture" ]]; then
  # Internal RCH job entry: generate the source on the worker because target/
  # is deliberately excluded from source synchronization.
  gcc -O2 -pthread -o "${FIXTURE_BIN}" "${FIXTURE_SRC}"
  exit $?
fi
if ! RCH_REQUIRE_REMOTE=1 rch exec --job --result-dir target/runtime_math_killswitch_e2e -- bash scripts/check_runtime_math_killswitch_e2e.sh --compile-fixture; then
  echo "FAIL: compilation failed"
  exit 1
fi
echo "Compiled: ${FIXTURE_BIN}"
echo ""

if [[ "${1:-}" == "--thread-signal" ]]; then
  timeout 15 env -u LD_PRELOAD FRANKENLIBC_PROBE_CONSTRUCTOR=1 "${FIXTURE_BIN}" --constructor-host-control
  rc=$?
  if [[ ${rc} -ne 0 ]]; then
    echo "FAIL: host constructor/thread/signal control (rc=${rc})"
    exit 1
  fi
  for probe_mode in strict hardened; do
    for math in off on; do
      timeout 15 env FRANKENLIBC_PROBE_CONSTRUCTOR=1 FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE="${probe_mode}" LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" "$1"
      rc=$?
      if [[ ${rc} -ne 0 ]]; then
        echo "FAIL: ${probe_mode}/${math} thread-signal probe (rc=${rc})"
        exit 1
      fi
    done
  done
  echo "PASS: thread joins and signal writes in both modes and switch states"
  exit 0
fi

if [[ "${1:-}" == "--bounds-repair" || "${1:-}" == "--healing-counter-first-use" ]]; then
  for math in off on; do
    timeout 15 env FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" "$1"
    rc=$?
    if [[ ${rc} -ne 0 ]]; then
      echo "FAIL: ${math} hardened $1 (rc=${rc})"
      exit 1
    fi
  done
  echo "PASS: $1 with runtime math off and on"
  exit 0
fi

if [[ "${1:-}" == "--policy-history" ]]; then
  for math in off on; do
    for history in successful adverse; do
      timeout 15 env FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" "--${history}-history"
      rc=$?
      if [[ ${rc} -ne 0 ]]; then
        echo "FAIL: ${math}/${history} history probe (rc=${rc})"
        exit 1
      fi
    done
  done
  echo "History observations only: compare action/profile; counters or risk alone do not prove policy influence."
  exit 0
fi

# The old gate only checked hardened mode and the switch accessor. Strict mode
# has a separate observation path; require its actual counter to remain still.
echo "--- Strict mode: math off must stop kernel decisions ---"
output=$(timeout 10 env FRANKENLIBC_RUNTIME_MATH=off FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 0 ]]; then
  echo "FAIL: strict math-off control still consults kernel (rc=${rc})"
  exit 1
fi

echo "--- Strict mode: math on must exercise the matched workload ---"
output=$(timeout 10 env FRANKENLIBC_RUNTIME_MATH=on FRANKENLIBC_MODE=strict LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -ne 1 ]]; then
  echo "FAIL: strict math-on control did not exercise kernel (rc=${rc})"
  exit 1
fi

# Test 1: Kill-switch OFF - runtime-math should be disabled
echo "--- Test 1: FRANKENLIBC_RUNTIME_MATH=off ---"
output=$(timeout 10 env FRANKENLIBC_RUNTIME_MATH=off FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" 2>&1)
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
output=$(timeout 10 env FRANKENLIBC_RUNTIME_MATH=on FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" 2>&1)
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
output=$(timeout 10 env -u FRANKENLIBC_RUNTIME_MATH FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" 2>&1)
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
output=$(timeout 10 env FRANKENLIBC_RUNTIME_MATH=invalid FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" 2>&1)
rc=$?
echo "${output}"
if [[ ${rc} -eq 1 ]]; then
  echo "PASS: invalid value falls back to runtime-math enabled"
else
  echo "FAIL: invalid value should fall back to runtime-math enabled"
  exit 1
fi
echo ""

# Test 5: Operations smoke only; this does not drive invalid-pointer validation.
echo "--- Test 5: Basic operations with math disabled ---"
output=$(timeout 10 env FRANKENLIBC_RUNTIME_MATH=off FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" sh -c 'ls /tmp > /dev/null' 2>&1)
rc=$?
if [[ ${rc} -eq 0 ]]; then
  echo "PASS: basic operations work with runtime-math disabled"
else
  echo "FAIL: basic operations should work with runtime-math disabled"
  exit 1
fi
echo ""

# Write summary JSON
SUMMARY_FILE="${OUT_DIR}/runtime_math_killswitch_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "runtime_math_killswitch_e2e.v1",
  "bead_id": "bd-06bxm.9",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "lib_path": "${LIB_PATH}",
  "fixture_bin": "${FIXTURE_BIN}",
  "tests": {
    "strict_off_stops_decisions": "pass",
    "strict_on_exercises_decisions": "pass",
    "off_disables_math": "pass",
    "on_enables_math": "pass",
    "default_enables_math": "pass",
    "invalid_falls_back_to_on": "pass",
    "basic_operations_with_math_off": "pass"
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
