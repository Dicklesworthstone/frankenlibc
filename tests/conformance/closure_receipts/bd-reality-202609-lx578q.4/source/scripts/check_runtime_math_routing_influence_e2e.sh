#!/usr/bin/env bash
# check_runtime_math_routing_influence_e2e.sh — Causal Runtime-Math Routing Proof (bd-reality-202609-lx578q.4)
#
# Proves on a release libfrankenlibc_abi.so (cfg(not(test)), default features) that:
# 1. Hot cached hardened families (StringMemory) observe runtime adverse signals,
#    update CACHED_HOT_HARDENED_DECISION, override static FFI-PCC fast-exit, tighten
#    TLS_CACHE warm integrity cadence (1-in-16 -> 1-in-1), and catch non-tail heap
#    canary corruption on strlen() call #1, while matched benign and math=off controls
#    keep 1-in-16 warm cadence (and still catch corruption within 16 reads).
# 2. Synchronously kernel-routed syscall families (Socket send/recv) consume
#    escalated RuntimeDecision via known_remaining_for_decision, blocking a
#    canary-corrupted heap buffer with -1/EFAULT on send() call #1 after adverse
#    Socket history while allowing all valid syscalls/buffers and matching benign
#    + math=off controls.
# 3. Strict mode output and errno match live host glibc in the same invocation, and
#    separated route counts + real ns/op timings against dlmopen(LM_ID_NEWLM, "libc.so.6")
#    are recorded without invented numbers or weakened gates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/data/tmp/cargo-target}"
export CARGO_TARGET_DIR

OUT_DIR="${REPO_ROOT}/target/runtime_math_routing_influence_e2e"
mkdir -p "${OUT_DIR}"

LIB_CANDIDATES=(
  "${FRANKENLIBC_SMOKE_LIB_PATH:-}"
  "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
  "${REPO_ROOT}/target/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -n "${candidate}" && -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" ]]; then
  echo "FAIL: could not locate release libfrankenlibc_abi.so (set FRANKENLIBC_SMOKE_LIB_PATH or build --release)" >&2
  exit 1
fi

LIB_SHA256="$(sha256sum "${LIB_PATH}" | awk '{print $1}')"
FIXTURE_SRC="${OUT_DIR}/fixture_routing_influence.c"
FIXTURE_BIN="${OUT_DIR}/fixture_routing_influence"
REPORT_JSON="${OUT_DIR}/runtime_math_routing_influence_report.v1.json"

cat > "${FIXTURE_SRC}" <<'ENDC'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <gnu/lib-names.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct decision_snapshot {
    uint64_t evidence_seqno;
    uint32_t family;
    uint32_t profile;
    uint32_t action;
    uint32_t risk_upper_bound_ppm;
    uint32_t policy_id;
    uint32_t reserved;
};

struct route_counts_snapshot {
    uint64_t abi_kernel_decisions;
    uint64_t pipeline_kernel_decisions;
    uint64_t independent_bounds_validations;
    uint64_t tls_cache_hits;
    uint64_t canary_failures;
    uint64_t fingerprint_failures;
    uint64_t ffi_pcc_decisions;
    uint64_t hot_cached_decisions;
    uint64_t math_off_bypasses;
    uint32_t warm_integrity_cadence_mask;
    uint32_t hot_escalated_mask;
};

extern int __frankenlibc_is_runtime_ready(void) __attribute__((weak));
extern int __frankenlibc_is_runtime_math_enabled(void) __attribute__((weak));
extern uint64_t __frankenlibc_decision_count(void) __attribute__((weak));
extern uint64_t __frankenlibc_healing_action_count(unsigned) __attribute__((weak));
extern int __frankenlibc_runtime_decision_snapshot(struct decision_snapshot *) __attribute__((weak));
extern int __frankenlibc_runtime_route_counts(struct route_counts_snapshot *) __attribute__((weak));

static int require_exports(void) {
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_is_runtime_math_enabled ||
        !__frankenlibc_decision_count || !__frankenlibc_healing_action_count ||
        !__frankenlibc_runtime_decision_snapshot || !__frankenlibc_runtime_route_counts) {
        fprintf(stderr, "FAIL: missing FrankenLibC runtime diagnostic exports\n");
        return 0;
    }
    if (!__frankenlibc_is_runtime_ready()) {
        fprintf(stderr, "FAIL: runtime is not ready\n");
        return 0;
    }
    return 1;
}

static int run_hot_probe(int adverse) {
    if (!require_exports()) return 2;

    size_t (*volatile strlen_fn)(const char *) = strlen;
    void *(*volatile memset_fn)(void *, int, size_t) = memset;

    unsigned char *buf_a = (unsigned char *)malloc(64);
    char *buf_b[3] = {NULL, NULL, NULL};
    if (!buf_a) return 2;
    memset_fn(buf_a, 'A', 64);

    for (int b = 0; b < 3; ++b) {
        buf_b[b] = (char *)malloc(256);
        if (!buf_b[b]) return 2;
        memset_fn(buf_b[b], 0, 256);
        memcpy(buf_b[b], "0123456789abcdef", 17);
    }

    struct route_counts_snapshot before_routes = {0};
    struct route_counts_snapshot after_routes = {0};
    if (__frankenlibc_runtime_route_counts(&before_routes) != 1) return 2;
    uint64_t heals_before = __frankenlibc_healing_action_count(1);

    /* ConformalRiskEngine recomputes upper_bound_ppm on RECOMPUTE_CADENCE = 64. */
    for (int i = 0; i < 64; ++i) {
        if (adverse) {
            /* Deliberate OOB memset request clamped safely to 64B in hardened mode. */
            memset_fn(buf_a, 'X', 128);
        } else {
            memset_fn(buf_a, 'X', 32);
        }
    }
    for (size_t j = 0; j < (adverse ? 64u : 32u); ++j) {
        if (buf_a[j] != 'X') return 2;
    }

    uint64_t heals_after = __frankenlibc_healing_action_count(1);

    /* Warm all 3 independent buffers in the 4-entry TLS_CACHE after history so
     * heal-log allocations during the history phase cannot evict them. */
    for (int b = 0; b < 3; ++b) {
        if (strlen_fn(buf_b[b]) != 16) {
            fprintf(stderr, "FAIL: initial strlen warm check b=%d\n", b);
            return 2;
        }
    }

    /* Probe 3 consecutive independent warm buffers: under 1-in-16 cadence (mask=15),
     * at most 1 of 3 consecutive ticks can be 0 mod 16; under escalated 1-in-1
     * cadence (mask=0), all 3 of 3 are verified and clamped to 0 immediately. */
    unsigned char orig_canary[3] = {0, 0, 0};
    int caught_immediate = 0;
    struct decision_snapshot snap = {0};
    int snap_ok = 0;
    for (int b = 0; b < 3; ++b) {
        volatile unsigned char *canary_byte = (volatile unsigned char *)buf_b[b] + 256;
        orig_canary[b] = *canary_byte;
        *canary_byte = (unsigned char)(orig_canary[b] ^ 0xFFu);

        errno = 0;
        size_t first_len = strlen_fn(buf_b[b]);
        int saved_errno = errno;
        if (saved_errno != 0) {
            for (int r = 0; r <= b; ++r) {
                *((volatile unsigned char *)buf_b[r] + 256) = orig_canary[r];
            }
            return 2;
        }
        if (b == 0) {
            snap_ok = __frankenlibc_runtime_decision_snapshot(&snap);
        }
        if (first_len == 0) {
            ++caught_immediate;
        }
    }

    if (__frankenlibc_runtime_route_counts(&after_routes) != 1) {
        for (int b = 0; b < 3; ++b) {
            *((volatile unsigned char *)buf_b[b] + 256) = orig_canary[b];
        }
        return 2;
    }

    int caught_within_16 = 0;
    for (int b = 0; b < 3; ++b) {
        int caught_this = 0;
        for (int k = 0; k < 16; ++k) {
            if (strlen_fn(buf_b[b]) == 0) {
                caught_this = 1;
                break;
            }
        }
        if (caught_this) ++caught_within_16;
        *((volatile unsigned char *)buf_b[b] + 256) = orig_canary[b];
        free(buf_b[b]);
    }
    free(buf_a);

    printf("probe=hot adverse=%d math_enabled=%d heals_delta=%lu abi_decisions_delta=%lu "
           "pipeline_decisions_delta=%lu bounds_delta=%lu tls_hits_delta=%lu "
           "canary_failures_delta=%lu hot_cached_delta=%lu math_off_delta=%lu "
           "cadence_mask=%u escalated_mask=%u snap_ok=%d snap_family=%u snap_action=%u "
           "snap_risk=%u caught_immediate=%d caught_within_16=%d\n",
           adverse,
           __frankenlibc_is_runtime_math_enabled(),
           heals_after - heals_before,
           after_routes.abi_kernel_decisions - before_routes.abi_kernel_decisions,
           after_routes.pipeline_kernel_decisions - before_routes.pipeline_kernel_decisions,
           after_routes.independent_bounds_validations - before_routes.independent_bounds_validations,
           after_routes.tls_cache_hits - before_routes.tls_cache_hits,
           after_routes.canary_failures - before_routes.canary_failures,
           after_routes.hot_cached_decisions - before_routes.hot_cached_decisions,
           after_routes.math_off_bypasses - before_routes.math_off_bypasses,
           after_routes.warm_integrity_cadence_mask,
           after_routes.hot_escalated_mask,
           snap_ok,
           snap.family,
           snap.action,
           snap.risk_upper_bound_ppm,
           caught_immediate,
           caught_within_16);
    return 0;
}

static int run_socket_probe(int adverse) {
    if (!require_exports()) return 2;

    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("FAIL: socketpair");
        return 2;
    }

    unsigned char *buf[3] = {NULL, NULL, NULL};
    unsigned char rx[16] = {0};
    for (int b = 0; b < 3; ++b) {
        buf[b] = (unsigned char *)malloc(256);
        if (!buf[b]) return 2;
        memset(buf[b], 0, 256);
        memcpy(buf[b], "PINGPONG", 8);
        /* Warm all 3 buffers in TLS_CACHE before driving Socket history. */
        if (send(sv[0], buf[b], 8, 0) != 8 || recv(sv[1], rx, 8, 0) != 8 ||
            memcmp(rx, "PINGPONG", 8) != 0) {
            fprintf(stderr, "FAIL: initial socketpair warm check b=%d\n", b);
            return 2;
        }
    }

    struct route_counts_snapshot before_routes = {0};
    struct route_counts_snapshot after_routes = {0};
    if (__frankenlibc_runtime_route_counts(&before_routes) != 1) return 2;

    for (int i = 0; i < 4096; ++i) {
        int fd = socket(AF_UNIX, adverse ? -1 : SOCK_STREAM, 0);
        if (adverse) {
            if (fd != -1 || errno != EINVAL) return 2;
        } else {
            if (fd < 0 || close(fd) != 0) return 2;
        }
    }

    /* Verify valid uncorrupted syscall + stack buffer still succeeds 100%. */
    const char ok_msg[4] = {'O', 'K', 'A', 'Y'};
    errno = 0;
    if (send(sv[0], ok_msg, 4, 0) != 4 || errno != 0 ||
        recv(sv[1], rx, 4, 0) != 4 || memcmp(rx, "OKAY", 4) != 0) {
        fprintf(stderr, "FAIL: valid socket send/recv failed after history\n");
        return 2;
    }

    unsigned char orig_canary[3] = {0, 0, 0};
    int caught_immediate = 0;
    struct decision_snapshot snap = {0};
    int snap_ok = 0;
    for (int b = 0; b < 3; ++b) {
        volatile unsigned char *canary_byte = (volatile unsigned char *)buf[b] + 256;
        orig_canary[b] = *canary_byte;
        *canary_byte = (unsigned char)(orig_canary[b] ^ 0xFFu);

        errno = 0;
        ssize_t first_rc = send(sv[0], buf[b], 8, 0);
        int first_errno = errno;
        if (first_rc == 8) {
            if (recv(sv[1], rx, 8, 0) != 8) {
                for (int r = 0; r <= b; ++r) {
                    *((volatile unsigned char *)buf[r] + 256) = orig_canary[r];
                }
                return 2;
            }
        } else if (first_rc == -1 && first_errno == EFAULT) {
            ++caught_immediate;
        }
        if (b == 0) {
            snap_ok = __frankenlibc_runtime_decision_snapshot(&snap);
        }
    }

    if (__frankenlibc_runtime_route_counts(&after_routes) != 1) {
        for (int b = 0; b < 3; ++b) {
            *((volatile unsigned char *)buf[b] + 256) = orig_canary[b];
        }
        return 2;
    }

    int caught_within_16 = 0;
    for (int b = 0; b < 3; ++b) {
        int caught_this = 0;
        for (int k = 0; k < 16; ++k) {
            errno = 0;
            ssize_t rc = send(sv[0], buf[b], 8, 0);
            if (rc == -1 && errno == EFAULT) {
                caught_this = 1;
                break;
            } else if (rc == 8) {
                if (recv(sv[1], rx, 8, 0) != 8) break;
            }
        }
        if (caught_this) ++caught_within_16;
        *((volatile unsigned char *)buf[b] + 256) = orig_canary[b];
        free(buf[b]);
    }
    close(sv[0]);
    close(sv[1]);

    printf("probe=socket adverse=%d math_enabled=%d abi_decisions_delta=%lu "
           "pipeline_decisions_delta=%lu bounds_delta=%lu canary_failures_delta=%lu "
           "math_off_delta=%lu snap_ok=%d snap_family=%u snap_profile=%u snap_action=%u "
           "snap_risk=%u caught_immediate=%d caught_within_16=%d\n",
           adverse,
           __frankenlibc_is_runtime_math_enabled(),
           after_routes.abi_kernel_decisions - before_routes.abi_kernel_decisions,
           after_routes.pipeline_kernel_decisions - before_routes.pipeline_kernel_decisions,
           after_routes.independent_bounds_validations - before_routes.independent_bounds_validations,
           after_routes.canary_failures - before_routes.canary_failures,
           after_routes.math_off_bypasses - before_routes.math_off_bypasses,
           snap_ok,
           snap.family,
           snap.profile,
           snap.action,
           snap.risk_upper_bound_ppm,
           caught_immediate,
           caught_within_16);
    return 0;
}

typedef size_t (*strlen_fn_t)(const char *);
typedef ssize_t (*send_fn_t)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn_t)(int, void *, size_t, int);
typedef int *(*errno_loc_fn_t)(void);
typedef int (*clock_fn_t)(clockid_t, struct timespec *);

static uint64_t elapsed_ns(struct timespec a, struct timespec b) {
    return (uint64_t)(b.tv_sec - a.tv_sec) * UINT64_C(1000000000) +
           (uint64_t)((int64_t)b.tv_nsec - (int64_t)a.tv_nsec);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int run_same_invocation_bench(void) {
    if (!require_exports()) return 2;

    void *host_ns = dlmopen(LM_ID_NEWLM, LIBC_SO, RTLD_NOW | RTLD_LOCAL);
    if (!host_ns) {
        fprintf(stderr, "FAIL: dlmopen(%s): %s\n", LIBC_SO, dlerror());
        return 2;
    }
    strlen_fn_t host_strlen = (strlen_fn_t)dlsym(host_ns, "strlen");
    send_fn_t host_send = (send_fn_t)dlsym(host_ns, "send");
    recv_fn_t host_recv = (recv_fn_t)dlsym(host_ns, "recv");
    errno_loc_fn_t host_errno_loc = (errno_loc_fn_t)dlsym(host_ns, "__errno_location");
    clock_fn_t host_clock = (clock_fn_t)dlsym(host_ns, "clock_gettime");
    if (!host_strlen || !host_send || !host_recv || !host_errno_loc || !host_clock) {
        fprintf(stderr, "FAIL: dlsym on isolated host glibc failed\n");
        return 2;
    }

    volatile strlen_fn_t fl_strlen = strlen;
    volatile strlen_fn_t host_strlen_v = host_strlen;
    volatile send_fn_t fl_send = send;
    volatile recv_fn_t fl_recv = recv;
    volatile send_fn_t host_send_v = host_send;
    volatile recv_fn_t host_recv_v = host_recv;

    char *heap_str = (char *)malloc(256);
    if (!heap_str) return 2;
    memset(heap_str, 'q', 200);
    heap_str[200] = '\0';

    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
    unsigned char rx[8] = {0};

    /* Warmup */
    if (fl_strlen(heap_str) != 200 || host_strlen_v(heap_str) != 200) return 2;
    if (fl_send(sv[0], heap_str, 8, 0) != 8 || fl_recv(sv[1], rx, 8, 0) != 8) return 2;
    if (host_send_v(sv[0], heap_str, 8, 0) != 8 || host_recv_v(sv[1], rx, 8, 0) != 8) return 2;

    struct route_counts_snapshot r0 = {0}, r1 = {0};
    if (__frankenlibc_runtime_route_counts(&r0) != 1) return 2;

    const int ROUNDS = 9;
    const int STRLEN_ITERS = 65536;
    const int SOCK_ITERS = 4096;
    uint64_t fl_strlen_samples[9], gl_strlen_samples[9];
    uint64_t fl_sock_samples[9], gl_sock_samples[9];

    for (int round = 0; round < ROUNDS; ++round) {
        for (int turn = 0; turn < 2; ++turn) {
            int lane = (round + turn) & 1;
            struct timespec t0, t1;
            size_t acc = 0;
            if (lane == 0) {
                errno = 0;
                host_clock(CLOCK_MONOTONIC_RAW, &t0);
                for (int i = 0; i < STRLEN_ITERS; ++i) {
                    char *p = heap_str;
                    __asm__ volatile("" : "+r"(p) : : "memory");
                    acc += fl_strlen(p);
                }
                host_clock(CLOCK_MONOTONIC_RAW, &t1);
                if (acc != (size_t)STRLEN_ITERS * 200u || errno != 0) return 2;
                fl_strlen_samples[round] = elapsed_ns(t0, t1);
            } else {
                int *herr = host_errno_loc();
                *herr = 0;
                host_clock(CLOCK_MONOTONIC_RAW, &t0);
                for (int i = 0; i < STRLEN_ITERS; ++i) {
                    char *p = heap_str;
                    __asm__ volatile("" : "+r"(p) : : "memory");
                    acc += host_strlen_v(p);
                }
                host_clock(CLOCK_MONOTONIC_RAW, &t1);
                if (acc != (size_t)STRLEN_ITERS * 200u || *herr != 0) return 2;
                gl_strlen_samples[round] = elapsed_ns(t0, t1);
            }
        }
        for (int turn = 0; turn < 2; ++turn) {
            int lane = (round + turn) & 1;
            struct timespec t0, t1;
            if (lane == 0) {
                errno = 0;
                host_clock(CLOCK_MONOTONIC_RAW, &t0);
                for (int i = 0; i < SOCK_ITERS; ++i) {
                    if (fl_send(sv[0], heap_str, 8, 0) != 8 || fl_recv(sv[1], rx, 8, 0) != 8)
                        return 2;
                }
                host_clock(CLOCK_MONOTONIC_RAW, &t1);
                if (errno != 0) return 2;
                fl_sock_samples[round] = elapsed_ns(t0, t1);
            } else {
                int *herr = host_errno_loc();
                *herr = 0;
                host_clock(CLOCK_MONOTONIC_RAW, &t0);
                for (int i = 0; i < SOCK_ITERS; ++i) {
                    if (host_send_v(sv[0], heap_str, 8, 0) != 8 || host_recv_v(sv[1], rx, 8, 0) != 8)
                        return 2;
                }
                host_clock(CLOCK_MONOTONIC_RAW, &t1);
                if (*herr != 0) return 2;
                gl_sock_samples[round] = elapsed_ns(t0, t1);
            }
        }
    }

    if (__frankenlibc_runtime_route_counts(&r1) != 1) return 2;
    qsort(fl_strlen_samples, ROUNDS, sizeof(uint64_t), cmp_u64);
    qsort(gl_strlen_samples, ROUNDS, sizeof(uint64_t), cmp_u64);
    qsort(fl_sock_samples, ROUNDS, sizeof(uint64_t), cmp_u64);
    qsort(gl_sock_samples, ROUNDS, sizeof(uint64_t), cmp_u64);

    double fl_strlen_ns = (double)fl_strlen_samples[ROUNDS / 2] / (double)STRLEN_ITERS;
    double gl_strlen_ns = (double)gl_strlen_samples[ROUNDS / 2] / (double)STRLEN_ITERS;
    double fl_sock_ns = (double)fl_sock_samples[ROUNDS / 2] / (double)SOCK_ITERS;
    double gl_sock_ns = (double)gl_sock_samples[ROUNDS / 2] / (double)SOCK_ITERS;

    printf("probe=bench mode=%s math_enabled=%d strlen_fl_ns=%.3f strlen_glibc_ns=%.3f "
           "sendrecv_fl_ns=%.3f sendrecv_glibc_ns=%.3f abi_decisions_delta=%lu "
           "pipeline_decisions_delta=%lu bounds_delta=%lu tls_hits_delta=%lu "
           "ffi_pcc_delta=%lu hot_cached_delta=%lu math_off_delta=%lu\n",
           getenv("FRANKENLIBC_MODE") ? getenv("FRANKENLIBC_MODE") : "strict",
           __frankenlibc_is_runtime_math_enabled(),
           fl_strlen_ns,
           gl_strlen_ns,
           fl_sock_ns,
           gl_sock_ns,
           r1.abi_kernel_decisions - r0.abi_kernel_decisions,
           r1.pipeline_kernel_decisions - r0.pipeline_kernel_decisions,
           r1.independent_bounds_validations - r0.independent_bounds_validations,
           r1.tls_cache_hits - r0.tls_cache_hits,
           r1.ffi_pcc_decisions - r0.ffi_pcc_decisions,
           r1.hot_cached_decisions - r0.hot_cached_decisions,
           r1.math_off_bypasses - r0.math_off_bypasses);

    close(sv[0]);
    close(sv[1]);
    free(heap_str);
    dlclose(host_ns);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (strcmp(argv[1], "--hot-adverse") == 0) return run_hot_probe(1);
    if (strcmp(argv[1], "--hot-benign") == 0) return run_hot_probe(0);
    if (strcmp(argv[1], "--socket-adverse") == 0) return run_socket_probe(1);
    if (strcmp(argv[1], "--socket-benign") == 0) return run_socket_probe(0);
    if (strcmp(argv[1], "--bench-same-invocation") == 0) return run_same_invocation_bench();
    return 2;
}
ENDC

gcc -O2 -pthread -fPIE -pie -o "${FIXTURE_BIN}" "${FIXTURE_SRC}" -ldl

echo "=== Causal Runtime-Math Routing Influence Gate (bd-reality-202609-lx578q.4) ==="
echo "Library: ${LIB_PATH} (sha256=${LIB_SHA256})"

HOT_ON_ADV="$(timeout 20 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=on LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --hot-adverse)"
HOT_ON_BEN="$(timeout 20 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=on LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --hot-benign)"
HOT_OFF_ADV="$(timeout 20 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=off LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --hot-adverse)"

SOCK_ON_ADV="$(timeout 30 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=on LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --socket-adverse)"
SOCK_ON_BEN="$(timeout 30 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=on LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --socket-benign)"
SOCK_OFF_ADV="$(timeout 30 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=off LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --socket-adverse)"

BENCH_STRICT="$(timeout 30 env FRANKENLIBC_MODE=strict FRANKENLIBC_RUNTIME_MATH=on LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --bench-same-invocation)"
BENCH_HARDENED_ON="$(timeout 30 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=on LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --bench-same-invocation)"
BENCH_HARDENED_OFF="$(timeout 30 env FRANKENLIBC_MODE=hardened FRANKENLIBC_RUNTIME_MATH=off LD_PRELOAD="${LIB_PATH}" "${FIXTURE_BIN}" --bench-same-invocation)"

printf '%s\n' \
  "${HOT_ON_ADV}" "${HOT_ON_BEN}" "${HOT_OFF_ADV}" \
  "${SOCK_ON_ADV}" "${SOCK_ON_BEN}" "${SOCK_OFF_ADV}" \
  "${BENCH_STRICT}" "${BENCH_HARDENED_ON}" "${BENCH_HARDENED_OFF}"

python3 - "${LIB_PATH}" "${LIB_SHA256}" "${REPORT_JSON}" \
  "${HOT_ON_ADV}" "${HOT_ON_BEN}" "${HOT_OFF_ADV}" \
  "${SOCK_ON_ADV}" "${SOCK_ON_BEN}" "${SOCK_OFF_ADV}" \
  "${BENCH_STRICT}" "${BENCH_HARDENED_ON}" "${BENCH_HARDENED_OFF}" <<'PY'
import json
import sys
from datetime import datetime, timezone

(
    lib_path,
    lib_sha256,
    report_path,
    hot_on_adv_s,
    hot_on_ben_s,
    hot_off_adv_s,
    sock_on_adv_s,
    sock_on_ben_s,
    sock_off_adv_s,
    bench_strict_s,
    bench_hard_on_s,
    bench_hard_off_s,
) = sys.argv[1:]


def parse_kv(line: str) -> dict:
    out = {}
    for tok in line.strip().split():
        k, v = tok.split("=", 1)
        try:
            out[k] = int(v)
        except ValueError:
            try:
                out[k] = float(v)
            except ValueError:
                out[k] = v
    return out


hot_on_adv = parse_kv(hot_on_adv_s)
hot_on_ben = parse_kv(hot_on_ben_s)
hot_off_adv = parse_kv(hot_off_adv_s)
sock_on_adv = parse_kv(sock_on_adv_s)
sock_on_ben = parse_kv(sock_on_ben_s)
sock_off_adv = parse_kv(sock_off_adv_s)
bench_strict = parse_kv(bench_strict_s)
bench_hard_on = parse_kv(bench_hard_on_s)
bench_hard_off = parse_kv(bench_hard_off_s)

# 1. Hot StringMemory matched-control causal assertions
assert hot_on_adv["heals_delta"] == 64, hot_on_adv
assert hot_on_adv["abi_decisions_delta"] >= 64, hot_on_adv
assert hot_on_adv["cadence_mask"] == 0, hot_on_adv
assert (hot_on_adv["escalated_mask"] & (1 << 2)) != 0, hot_on_adv
assert hot_on_adv["hot_cached_delta"] >= 3, hot_on_adv
assert hot_on_adv["snap_ok"] == 1 and hot_on_adv["snap_family"] in (1, 2), hot_on_adv
assert hot_on_adv["caught_immediate"] == 3 and hot_on_adv["caught_within_16"] == 3, hot_on_adv
assert hot_on_adv["canary_failures_delta"] >= 3, hot_on_adv

assert hot_on_ben["heals_delta"] == 0, hot_on_ben
assert hot_on_ben["cadence_mask"] == 15, hot_on_ben
assert (hot_on_ben["escalated_mask"] & (1 << 2)) == 0, hot_on_ben
assert hot_on_ben["caught_immediate"] <= 1 and hot_on_ben["caught_within_16"] == 3, hot_on_ben

assert hot_off_adv["heals_delta"] == 64, hot_off_adv
assert hot_off_adv["abi_decisions_delta"] == 0, hot_off_adv
assert hot_off_adv["pipeline_decisions_delta"] == 0, hot_off_adv
assert hot_off_adv["cadence_mask"] == 15, hot_off_adv
assert hot_off_adv["caught_immediate"] <= 1 and hot_off_adv["caught_within_16"] == 3, hot_off_adv

# 2. Synchronous Socket send() matched-control causal assertions
assert sock_on_adv["abi_decisions_delta"] >= 4098, sock_on_adv
assert sock_on_adv["snap_ok"] == 1 and sock_on_adv["snap_family"] == 13, sock_on_adv
assert sock_on_adv["snap_risk"] >= 750000, sock_on_adv
assert sock_on_adv["caught_immediate"] == 3 and sock_on_adv["caught_within_16"] == 3, sock_on_adv
assert sock_on_adv["canary_failures_delta"] >= 3, sock_on_adv

assert sock_on_ben["snap_risk"] < 750000, sock_on_ben
assert sock_on_ben["caught_immediate"] <= 1 and sock_on_ben["caught_within_16"] == 3, sock_on_ben

assert sock_off_adv["abi_decisions_delta"] == 0, sock_off_adv
assert sock_off_adv["math_off_delta"] >= 4098, sock_off_adv
assert sock_off_adv["caught_immediate"] <= 1 and sock_off_adv["caught_within_16"] == 3, sock_off_adv

# 3. Same-invocation route separation assertions
assert bench_hard_off["abi_decisions_delta"] == 0, bench_hard_off
assert bench_hard_off["pipeline_decisions_delta"] == 0, bench_hard_off
assert bench_hard_off["math_off_delta"] >= 8192, bench_hard_off
assert bench_hard_on["abi_decisions_delta"] >= 8192, bench_hard_on

report = {
    "schema_version": "runtime_math_routing_influence_report.v1",
    "bead_id": "bd-reality-202609-lx578q.4",
    "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "lib_path": lib_path,
    "lib_sha256": lib_sha256,
    "interventions": {
        "hot_string_memory": {
            "hardened_math_on_adverse": hot_on_adv,
            "hardened_math_on_benign": hot_on_ben,
            "hardened_math_off_adverse": hot_off_adv,
        },
        "synchronous_socket_send": {
            "hardened_math_on_adverse": sock_on_adv,
            "hardened_math_on_benign": sock_on_ben,
            "hardened_math_off_adverse": sock_off_adv,
        },
    },
    "same_invocation_benchmarks": {
        "strict_math_on": bench_strict,
        "hardened_math_on": bench_hard_on,
        "hardened_math_off": bench_hard_off,
    },
    "overall_status": "pass",
}

with open(report_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")

print(f"PASS: wrote causal routing influence report to {report_path}")
PY
