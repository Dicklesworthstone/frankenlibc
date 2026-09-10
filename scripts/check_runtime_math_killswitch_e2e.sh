#!/usr/bin/env bash
# check_runtime_math_killswitch_e2e.sh — E2E test for runtime-math kill-switch (bd-06bxm.9)
#
# Verifies that:
# 1. FRANKENLIBC_RUNTIME_MATH=off disables runtime-math kernel consultation
# 2. Basic operations still run when math is disabled (not a bounds-check proof)
# 3. FRANKENLIBC_RUNTIME_MATH=on (or absent) enables runtime-math
# 4. Invalid values fall back to on
# --policy-history runs matched histories across fixed horizons and reports decisions; it
# checks consultation and liveness, not whether action/profile influence exists.
# --bounds-repair checks source-bound clamping with math off and on in hardened
# mode. It never runs the intentionally oversized copy against strict libc.
# --thread-signal exercises concurrent sockets and writes from a signal handler;
# delivery is between socket calls, not proof of interruption inside a lock.
# --policy-cost measures warm socket+close batches against live glibc in the
# SAME process. Raw times are advisory, not a routing-influence or speedup gate.
# --socket-mxcsr checks x86_64 caller flags, rounding, and inexact trap masks
# against live host and both modes/switch states; also runs in the default suite.
# --startup-auxv compares owned-startup metadata with the original kernel vector.
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
#define _GNU_SOURCE
#include <dlfcn.h>
/* fixture_killswitch.c — verify FRANKENLIBC_RUNTIME_MATH kill-switch */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));
extern int __frankenlibc_is_runtime_math_enabled(void) __attribute__((weak));
extern uint64_t __frankenlibc_decision_count(void) __attribute__((weak));
extern uint64_t __frankenlibc_healing_action_count(unsigned) __attribute__((weak));
struct startup_snapshot {
    size_t argc, argv_count, env_count, auxv_count;
    int secure_mode;
};
extern int __frankenlibc_startup_snapshot(struct startup_snapshot*) __attribute__((weak));

static int signal_pipe[2];
static int constructor_result = -1;
static int constructor_ready = -1;
static int constructor_calls;
static int init_order;
static int init_order_failed;
static int init_argc;
static char **init_argv;
static char **init_envp;

static void probe_preinit(int argc, char **argv, char **envp) {
    if (init_order++ != 0) init_order_failed = 1;
    init_argc = argc;
    init_argv = argv;
    init_envp = envp;
}
__attribute__((section(".preinit_array"), used))
static void (*const preinit_entry)(int, char **, char **) = probe_preinit;

/* Selected as DT_INIT by the fixture link command. */
void probe_elf_init(int argc, char **argv, char **envp) {
    if (init_order++ != 1 || argc != init_argc || argv != init_argv || envp != init_envp)
        init_order_failed = 1;
}

__attribute__((constructor(101))) static void probe_early_constructor(void) {
    if (init_order++ != 2) init_order_failed = 1;
}

__attribute__((constructor)) static void probe_constructor(void) {
    if (init_order++ != 3) init_order_failed = 1;
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
    if (init_order != 4 || init_order_failed || init_argc != 2 || !init_argv || !init_envp) {
        fprintf(stderr, "FAIL: constructor order/arguments (order=%d failed=%d argc=%d)\n",
                init_order, init_order_failed, init_argc);
        return 2;
    }
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

    uint64_t decisions_before = __frankenlibc_decision_count();
    /* Valid counterpart first; initialize through the guarded libc operation,
     * not through a diagnostic that may lazily initialize healing itself. */
    if (copy(dst, src, 8) != dst) return 2;
    for (size_t i = 0; i < 8; ++i) if (dst[i] != 'A' + i) return 2;
    for (size_t i = 0; i < 32; ++i) ((volatile unsigned char*)dst)[i] = 'J';
    uint64_t heals_before = __frankenlibc_healing_action_count(1);
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
    if (!__frankenlibc_is_runtime_math_enabled() && decisions_after != decisions_before) {
        fprintf(stderr, "FAIL: math-off bounds probe consulted a runtime kernel (%lu decisions)\n",
                decisions_after - decisions_before);
        return 2;
    }
    if (__frankenlibc_is_runtime_math_enabled() && decisions_after <= decisions_before) {
        fprintf(stderr, "FAIL: math-on bounds control never consulted the pointer kernel\n");
        return 2;
    }
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
static int policy_history(int adverse, int calls) {
    if (!__frankenlibc_runtime_decision_snapshot) {
        fprintf(stderr, "FAIL: decision snapshot export missing\n");
        return 2;
    }
    int failures = 0;
    for (int i = 0; i < calls; ++i) {
        int fd = socket(AF_UNIX, adverse ? -1 : SOCK_STREAM, 0);
        if (fd < 0) ++failures;
        else if (close(fd) != 0) return 2;
    }
    if (failures != (adverse ? calls : 0)) {
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
    printf("history=%s calls=%d failures=%d result=%d errno=%d sequence=%lu profile=%u action=%u risk=%u policy=%u\n",
           adverse ? "adverse" : "successful", calls, failures, fd < 0 ? -1 : 0,
           saved_errno, snapshot.evidence_seqno, snapshot.profile, snapshot.action,
           snapshot.risk_upper_bound_ppm, snapshot.policy_id);
    /* Evidence publication is sampled every 16384 ordinary decisions. Its
     * sequence can be zero even when the exact counter delta above is one. */
    return 0;
}

typedef int (*socket_fn)(int, int, int);
typedef int (*close_fn)(int);
typedef int (*clock_fn)(clockid_t, struct timespec*);

/* Whole socket+close pairs, not per-socket latency or an isolated kernel cost.
 * Both lanes use indirect calls, identical inputs, and their own errno slot.
 * Checking success/errno is included symmetrically in the measured work. */
static int socket_batch(socket_fn open_socket, close_fn close_socket, int *error,
                        clock_fn clock_now, uint64_t *elapsed) {
    struct timespec begin, end;
    if (clock_now(CLOCK_MONOTONIC_RAW, &begin) != 0) return 2;
    for (int i = 0; i < 8192; ++i) {
        *error = 0;
        int fd = open_socket(AF_UNIX, SOCK_STREAM, 0);
        int socket_error = *error;
        if (fd < 0) return 2;
        int closed = close_socket(fd);
        if (socket_error != 0 || closed != 0 || *error != 0) return 2;
    }
    if (clock_now(CLOCK_MONOTONIC_RAW, &end) != 0) return 2;
    int64_t ns = (int64_t)(end.tv_sec - begin.tv_sec) * INT64_C(1000000000)
               + end.tv_nsec - begin.tv_nsec;
    if (ns <= 0) return 2;
    *elapsed = (uint64_t)ns;
    return 0;
}

static int policy_cost(void) {
    /* An isolated namespace prevents the incumbent's internal calls from
     * resolving back into FrankenLibC. Keep the handle live until process exit. */
    /* FrankenLibC's dlmopen currently ignores lmid; do not mistake that path
     * for an isolated incumbent. Resolve the host loader explicitly. */
    void *(*host_dlmopen)(Lmid_t, const char*, int) =
        (void*(*)(Lmid_t, const char*, int))dlsym(RTLD_NEXT, "dlmopen");
    int (*host_dlinfo)(void*, int, void*) =
        (int(*)(void*, int, void*))dlsym(RTLD_NEXT, "dlinfo");
    if (!host_dlmopen || !host_dlinfo || host_dlmopen == dlmopen || host_dlinfo == dlinfo) {
        fprintf(stderr, "FAIL: host loader not resolved\n");
        return 2;
    }
    void *host = host_dlmopen(LM_ID_NEWLM, "libc.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!host) { fprintf(stderr, "FAIL: isolated live glibc unavailable\n"); return 2; }
    socket_fn host_socket = (socket_fn)dlsym(host, "socket");
    close_fn host_close = (close_fn)dlsym(host, "close");
    clock_fn host_clock = (clock_fn)dlsym(host, "clock_gettime");
    int *(*host_errno)(void) = (int*(*)(void))dlsym(host, "__errno_location");
    const char *(*host_version)(void) = (const char*(*)(void))dlsym(host, "gnu_get_libc_version");
    int (*host_dladdr)(const void*, Dl_info*) = (int(*)(const void*, Dl_info*))dlsym(host, "dladdr");
    Lmid_t namespace_id = LM_ID_BASE;
    Dl_info hs = {0}, hc = {0}, hv = {0}, fs = {0}, fc = {0}, diagnostic = {0};
    if (!host_socket || !host_close || !host_clock || !host_errno || !host_version || !host_dladdr ||
        host_dlinfo(host, RTLD_DI_LMID, &namespace_id) != 0 || namespace_id == LM_ID_BASE ||
        !host_dladdr((void*)host_socket, &hs) || !host_dladdr((void*)host_close, &hc) ||
        !host_dladdr((void*)host_version, &hv) || !host_dladdr((void*)socket, &fs) ||
        !host_dladdr((void*)close, &fc) || !host_dladdr((void*)__frankenlibc_decision_count, &diagnostic) ||
        hs.dli_fbase != hv.dli_fbase || hc.dli_fbase != hv.dli_fbase ||
        fs.dli_fbase != diagnostic.dli_fbase || fc.dli_fbase != diagnostic.dli_fbase ||
        hs.dli_fbase == fs.dli_fbase) {
        fprintf(stderr, "FAIL: incumbent/candidate symbol identity not established namespace=%ld symbols=%p/%p/%p/%p/%p/%p bases=%p/%p/%p/%p/%p/%p\n",
                (long)namespace_id, (void*)host_socket, (void*)host_close, (void*)host_clock,
                (void*)host_errno, (void*)host_version, (void*)host_dladdr,
                hs.dli_fbase, hc.dli_fbase, hv.dli_fbase, fs.dli_fbase, fc.dli_fbase, diagnostic.dli_fbase);
        return 2;
    }
    int *errors[2] = {&errno, host_errno()};
    if (!errors[1] || errors[0] == errors[1]) return 2;
    socket_fn opens[2] = {socket, host_socket};
    close_fn closes[2] = {close, host_close};
    /* Prove that each errno pointer observes its own implementation's errors;
     * two permanently-zero or wrongly selected slots must not pass parity. */
    for (int lane = 0; lane < 2; ++lane) {
        *errors[lane] = 0;
        int fd = opens[lane](AF_UNIX, -1, 0);
        int invalid_errno = *errors[lane];
        if (fd >= 0) (void)closes[lane](fd);
        if (fd != -1 || invalid_errno != EINVAL) {
            fprintf(stderr, "FAIL: errno negative control lane=%d result=%d errno=%d\n", lane, fd, invalid_errno);
            return 2;
        }
    }
    int enabled = __frankenlibc_is_runtime_math_enabled();
    /* Initialize diagnostics before collecting deltas. No diagnostic is in
     * the timed region, and the clock itself comes from the isolated glibc. */
    (void)__frankenlibc_decision_count();
    printf("policy_cost candidate=%s incumbent=%s glibc=%s namespace=%ld math=%d errno_control=EINVAL pairs=8192 warmup=3 min_samples=24 min_timed_ns=10000000000\n",
           fs.dli_fname, hs.dli_fname, host_version(), (long)namespace_id, enabled);
    uint64_t total = 0;
    int round = 0;
    while (round < 27 || total < UINT64_C(10000000000)) {
        uint64_t elapsed[2], decisions[2];
        for (int turn = 0; turn < 2; ++turn) {
            int lane = (round + turn) % 2;
            uint64_t before = __frankenlibc_decision_count();
            if (socket_batch(opens[lane], closes[lane], errors[lane], host_clock, &elapsed[lane]) != 0) {
                fprintf(stderr, "FAIL: socket-pair result/errno/clock round=%d lane=%d\n", round, lane);
                return 2;
            }
            decisions[lane] = __frankenlibc_decision_count() - before;
            if (decisions[lane] != (uint64_t)(lane == 0 ? enabled * 8192 : 0)) {
                fprintf(stderr, "FAIL: unexpected consultation count round=%d lane=%d count=%lu\n",
                        round, lane, decisions[lane]);
                return 2;
            }
        }
        if (round >= 3) {
            total += elapsed[0] + elapsed[1];
            printf("cost_sample=%d first=%s pairs=8192 franken_ns=%lu glibc_ns=%lu franken_decisions=%lu glibc_decisions=%lu result=success errno=0\n",
                   round - 3, round % 2 ? "glibc" : "franken", elapsed[0], elapsed[1], decisions[0], decisions[1]);
        }
        ++round;
    }
    printf("cost_complete samples=%d timed_ns=%lu verdict=ADVISORY routing_influence=unproven\n", round - 3, total);
    return 0;
}

int main(int argc, char** argv) {
    /* Diagnostic uses hardware directly so the fenv ABI under investigation
     * cannot conceal a change. A separate host flag prevents failed preloading
     * from silently satisfying the candidate gate with host libc. */
    int mxcsr_host = argc == 2 && strcmp(argv[1], "--socket-mxcsr-host-control") == 0;
    if (argc == 2 && (strcmp(argv[1], "--socket-mxcsr") == 0 || mxcsr_host)) {
        /* This accessor is an atomic read, not kernel initialization: preserve
         * coverage of the FIRST socket's initialization/boxing path. */
        if (!mxcsr_host && (!__frankenlibc_is_runtime_ready ||
                           !__frankenlibc_decision_count ||
                           !__frankenlibc_is_runtime_ready())) {
            fprintf(stderr, "FAIL: MXCSR candidate runtime is not loaded/ready\n");
            return 2;
        }
#if defined(__x86_64__)
        unsigned saved, after = 0, expected = 0;
        int failed = 0, sample = 0;
        __asm__ volatile ("stmxcsr %0" : "=m" (saved));
        for (unsigned trap_inexact = 0; trap_inexact < 2 && !failed; ++trap_inexact) {
            for (unsigned rounding = 0; rounding < 4 && !failed; ++rounding) {
                for (unsigned seeded = 0; seeded < 2 && !failed; ++seeded) {
                    expected = (0x1f80u & ~(trap_inexact << 12)) | (rounding << 13) | seeded;
                    for (sample = 0; sample < 4096; ++sample) {
                        __asm__ volatile ("ldmxcsr %0" : : "m" (expected) : "memory");
                        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
                        __asm__ volatile ("stmxcsr %0" : "=m" (after) : : "memory");
                        if (fd < 0 || after != expected) failed = 1;
                        if (fd >= 0 && close(fd) != 0) failed = 1;
                        if (failed) break;
                    }
                }
            }
        }
        __asm__ volatile ("ldmxcsr %0" : : "m" (saved) : "memory");
        printf("socket_mxcsr expected=%#x actual=%#x sample=%d result=%s\n",
               expected, after, sample, failed ? "FAIL" : "PASS");
        return failed ? 1 : 0;
#else
        fprintf(stderr, "socket MXCSR diagnostic requires x86_64\n");
        return 77;
#endif
    }
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
    if ((argc == 2 || argc == 3) &&
        (strcmp(argv[1], "--successful-history") == 0 ||
         strcmp(argv[1], "--adverse-history") == 0)) {
        int calls = 512;
        if (argc == 3) {
            /* Bounded diagnostic horizon, not a runtime policy override. */
            char *end;
            errno = 0;
            long parsed = strtol(argv[2], &end, 10);
            if (errno || end == argv[2] || *end || parsed < 1 || parsed > 16384)
                return 2;
            calls = (int)parsed;
        }
        return policy_history(strcmp(argv[1], "--adverse-history") == 0, calls);
    }
    if (argc == 2) {
        if (strcmp(argv[1], "--startup-auxv") == 0) {
            if (!__frankenlibc_startup_snapshot || !init_envp) return 2;
            size_t env_count = 0, pairs = 0;
            while (init_envp[env_count]) ++env_count;
            const uintptr_t *auxv = (const uintptr_t*)(init_envp + env_count + 1);
            int secure = -1;
            for (; pairs < 256; ++pairs) {
                if (auxv[2 * pairs] == 23) secure = auxv[2 * pairs + 1] != 0;
                if (auxv[2 * pairs] == 0) break;
            }
            struct startup_snapshot snapshot;
            if (pairs == 256 || secure < 0 || __frankenlibc_startup_snapshot(&snapshot) != 0)
                return 2;
            int ok = snapshot.argc == (size_t)argc && snapshot.argv_count == (size_t)argc &&
                     snapshot.env_count == env_count && snapshot.auxv_count == pairs &&
                     snapshot.secure_mode == secure;
            printf("startup_auxv expected=%zu observed=%zu secure_expected=%d secure_observed=%d result=%s\n",
                   pairs, snapshot.auxv_count, secure, snapshot.secure_mode, ok ? "PASS" : "FAIL");
            return ok ? 0 : 1;
        }
        if (strcmp(argv[1], "--policy-cost") == 0) return policy_cost();
        if (strcmp(argv[1], "--thread-signal") == 0) return thread_signal_probe();
        if (strcmp(argv[1], "--healing-counter-first-use") == 0) {
            if (!__frankenlibc_healing_action_count) return 2;
            uint64_t count = __frankenlibc_healing_action_count(1);
            if (__frankenlibc_healing_action_count(1) != count) return 2;
            if (__frankenlibc_healing_action_count(0) != UINT64_MAX ||
                __frankenlibc_healing_action_count(UINT32_MAX) != UINT64_MAX) return 2;
            printf("first_use_healing_counter=%lu repeated_read=stable\n", count);
            return 0;
        }
        if (strcmp(argv[1], "--bounds-repair") == 0) return bounds_repair();
        return 2;
    }
    if (argc != 1) return 2;
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
  gcc -O2 -pthread -fPIE -pie -Wl,-init,probe_elf_init -o "${FIXTURE_BIN}" "${FIXTURE_SRC}" -ldl || exit $?
  # PIC code keeps weak diagnostic imports dynamically resolvable even though
  # -no-pie makes the executable itself fixed-address (ELF ET_EXEC).
  gcc -O2 -pthread -fPIC -no-pie -Wl,-init,probe_elf_init -o "${FIXTURE_BIN}_nonpie" "${FIXTURE_SRC}" -ldl
  exit $?
fi
if ! RCH_REQUIRE_REMOTE=1 rch exec --job --result-dir target/runtime_math_killswitch_e2e -- bash scripts/check_runtime_math_killswitch_e2e.sh --compile-fixture; then
  echo "FAIL: compilation failed"
  exit 1
fi
echo "Compiled: ${FIXTURE_BIN}"
echo ""

if [[ "${1:-}" == "--startup-auxv" ]]; then
  for probe_bin in "${FIXTURE_BIN}" "${FIXTURE_BIN}_nonpie"; do
    for probe_mode in strict hardened; do
      timeout 15 env -u FRANKENLIBC_STARTUP_DELEGATE FRANKENLIBC_MODE="${probe_mode}" LD_PRELOAD="${LIB_PATH}" "${probe_bin}" --startup-auxv || exit 1
    done
  done
  exit 0
fi

if [[ -z "${1:-}" || "${1:-}" == "--socket-mxcsr" ]]; then
  echo "--- Socket MXCSR preservation: live host control ---"
  timeout 30 env -u LD_PRELOAD "${FIXTURE_BIN}" --socket-mxcsr-host-control || exit 1
  # A missing preload must be red, even though the host control is green.
  timeout 30 env -u LD_PRELOAD "${FIXTURE_BIN}" --socket-mxcsr
  rc=$?
  if [[ ${rc} -ne 2 ]]; then
    echo "FAIL: missing-preload negative control (rc=${rc})"
    exit 1
  fi
  for probe_mode in strict hardened; do
    for math in off on; do
      echo "MXCSR probe: ${probe_mode}/${math}"
      timeout 30 env FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE="${probe_mode}" LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --socket-mxcsr || exit 1
    done
  done
  if [[ "${1:-}" == "--socket-mxcsr" ]]; then exit 0; fi
fi

if [[ "${1:-}" == "--policy-cost" ]]; then
  for probe_mode in strict hardened; do
    for math in off on; do
      echo "Cost probe: ${probe_mode}/${math}"
      timeout 120 env FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE="${probe_mode}" LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" "$1"
      rc=$?
      if [[ ${rc} -ne 0 ]]; then
        echo "FAIL: ${probe_mode}/${math} cost probe (rc=${rc})"
        exit 1
      fi
    done
  done
  echo "PASS: matched socket-pair results and consultation counts; timings remain advisory"
  exit 0
fi

if [[ "${1:-}" == "--thread-signal" ]]; then
  for probe_bin in "${FIXTURE_BIN}" "${FIXTURE_BIN}_nonpie"; do
    echo "Constructor fixture: ${probe_bin}"
    timeout 15 env -u LD_PRELOAD FRANKENLIBC_PROBE_CONSTRUCTOR=1 "${probe_bin}" --constructor-host-control
    rc=$?
    if [[ ${rc} -ne 0 ]]; then
      echo "FAIL: host constructor/thread/signal control (rc=${rc})"
      exit 1
    fi
    for probe_mode in strict hardened; do
      for math in off on; do
        timeout 15 env FRANKENLIBC_PROBE_CONSTRUCTOR=1 FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE="${probe_mode}" LD_PRELOAD="${LIB_PATH}" "${probe_bin}" "$1"
        rc=$?
        if [[ ${rc} -ne 0 ]]; then
          echo "FAIL: ${probe_mode}/${math} thread-signal probe (rc=${rc})"
          exit 1
        fi
      done
    done
  done
  echo "PASS: PIE/non-PIE constructor order/arguments, thread joins and signal writes in both modes and switch states"
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
    for calls in 64 256 512 4096 16384; do
      for history in successful adverse; do
        echo "History probe: math=${math} calls=${calls} outcomes=${history}"
        timeout 15 env FRANKENLIBC_RUNTIME_MATH="${math}" FRANKENLIBC_MODE=hardened LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" "--${history}-history" "${calls}"
        rc=$?
        if [[ ${rc} -ne 0 ]]; then
          echo "FAIL: ${math}/${history}/${calls} history probe (rc=${rc})"
          exit 1
        fi
      done
    done
  done
  echo "History observations only: compare action/profile; socket consumes Deny but not Repair. A changed decision alone does not prove changed syscall routing."
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
    "socket_mxcsr_preserved": "pass",
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
