//! Integration gate test for `bd-rc0923-epic-eeuy4f.26` and `bd-f874go`:
//! verifies multi-threaded `malloc`/`free` + `calloc` strict fast-path wiring,
//! `fixture_fork_mt` byte-exact parity in `{strict, hardened}` modes, recycled-slot
//! `calloc` zero-initialization across all small size classes, overflow `ENOMEM`
//! handling, and 4-worker concurrent `malloc`/`calloc`/`free` churn under `LD_PRELOAD`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        Path::new(manifest_dir)
            .parent()
            .and_then(Path::parent)
            .expect("workspace root must exist")
            .to_path_buf()
    } else {
        std::env::current_dir().expect("cwd must exist")
    }
}

#[test]
fn malloc_mt_and_calloc_hot_path_contracts_are_wired() {
    let root = workspace_root();
    let src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/malloc_abi.rs"))
        .expect("malloc_abi.rs readable");

    assert!(src.contains("const KEY_SLOT_DIR_LEN: usize = 512;"));
    assert!(src.contains("unsafe extern \"C\" fn finish_alloc_st_fast("));
    assert!(src.contains("unsafe extern \"C\" fn finish_free_st_fast("));
    assert!(src.contains("unsafe fn zero_recycled_segment_slot("));
    assert!(src.contains("unsafe extern \"C\" fn calloc_strict_refill_from_slot("));
}

#[test]
fn malloc_mt_fork_and_calloc_live_preload_gate_passes() {
    let root = workspace_root();
    let explicit_lib = std::env::var_os("FRANKENLIBC_MALLOC_TEST_LIB").map(PathBuf::from);
    let lib = explicit_lib
        .clone()
        .unwrap_or_else(|| root.join("target/release/libfrankenlibc_abi.so"));
    if explicit_lib.is_some() {
        assert!(
            lib.is_file(),
            "FRANKENLIBC_MALLOC_TEST_LIB must point to an existing release libfrankenlibc_abi.so: {}",
            lib.display()
        );
    }

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "fl_malloc_mt_calloc_gate_{}_{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&tmp).expect("temp dir creatable");

    let probe_c = tmp.join("probe_mt_calloc.c");
    let probe_bin = tmp.join("probe_mt_calloc");
    fs::write(
        &probe_c,
        r#"#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WORKERS 4
#define OPS 200000L
#define RING 32

static pthread_barrier_t bar;
static unsigned char * volatile g_sig_ptr = NULL;
static unsigned char * volatile g_sig_small = NULL;
static volatile int g_sig_ok = 0;

static void *noop_native_thread(void *arg) { return arg; }

static void sigusr1_realloc_handler(int sig) {
    (void)sig;
    unsigned char *p = g_sig_ptr;
    unsigned char *q = (unsigned char *)realloc(p, 98304);
    unsigned char *s = g_sig_small;
    unsigned char *t = (unsigned char *)realloc(s, 1024);
    if (q != NULL && t != NULL) {
        int ok = 1;
        for (size_t i = 0; i < 65536; i += 257) {
            if (q[i] != (unsigned char)((i * 31u + 7u) & 0xffu)) {
                ok = 0;
                break;
            }
        }
        for (size_t i = 0; i < 256; i++) {
            if (t[i] != (unsigned char)((i * 17u + 3u) & 0xffu)) {
                ok = 0;
                break;
            }
        }
        g_sig_ptr = q;
        g_sig_small = t;
        g_sig_ok = ok;
    }
}

static void *worker(void *arg) {
    uint32_t st = (uint32_t)(uintptr_t)arg;
    void *ring[RING] = {0};
    pthread_barrier_wait(&bar);
    for (long i = 0; i < OPS; i++) {
        st ^= st << 13; st ^= st >> 17; st ^= st << 5;
        int slot = (int)(st & (RING - 1));
        size_t sz = 1 + ((st >> 5) % 4096);
        if (ring[slot]) free(ring[slot]);
        if ((i & 3) == 0) {
            unsigned char *p = (unsigned char *)calloc(1, sz);
            if (!p) abort();
            for (size_t k = 0; k < sz; k += (sz > 64 ? 17 : 1)) {
                if (p[k] != 0) {
                    fprintf(stderr, "non-zero calloc byte at sz=%zu off=%zu: 0x%02x\n", sz, k, p[k]);
                    abort();
                }
            }
            if (p[sz - 1] != 0) abort();
            memset(p, 0xA5, sz);
            ring[slot] = p;
        } else {
            unsigned char *p = (unsigned char *)malloc(sz);
            if (!p) abort();
            memset(p, 0x5A, sz < 64 ? sz : 64);
            p[sz - 1] = 0x5A;
            ring[slot] = p;
        }
    }
    for (int i = 0; i < RING; i++) free(ring[i]);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "sig-realloc") == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sigusr1_realloc_handler;
        if (sigaction(SIGUSR1, &sa, NULL) != 0) return 2;

        /* Phase 1: Pure single-threaded (!MULTI_THREADED) unlocked fallback-table path */
        for (int iter = 0; iter < 8; iter++) {
            unsigned char *old_free = (unsigned char *)malloc(65536);
            if (!old_free) return 3;
            free(old_free);
            unsigned char *buf = (unsigned char *)malloc(65536);
            unsigned char *sbuf = (unsigned char *)malloc(256);
            if (!buf || !sbuf) return 3;
            for (size_t i = 0; i < 65536; i++) buf[i] = (unsigned char)((i * 31u + 7u) & 0xffu);
            for (size_t i = 0; i < 256; i++) sbuf[i] = (unsigned char)((i * 17u + 3u) & 0xffu);
            g_sig_ok = 0;
            g_sig_ptr = buf;
            g_sig_small = sbuf;
            raise(SIGUSR1);
            if (!g_sig_ok) {
                fprintf(stderr, "ST signal handler realloc failed or lost payload bytes\n");
                return 4;
            }
        }

        /* Phase 2: Multi-threaded / native-thread path */
        pthread_t warm_th;
        if (pthread_create(&warm_th, NULL, noop_native_thread, NULL) != 0) return 2;
        if (pthread_join(warm_th, NULL) != 0) return 2;
        unsigned char *buf = (unsigned char *)malloc(65536);
        unsigned char *sbuf = (unsigned char *)malloc(256);
        if (!buf || !sbuf) return 3;
        for (size_t i = 0; i < 65536; i++) buf[i] = (unsigned char)((i * 31u + 7u) & 0xffu);
        for (size_t i = 0; i < 256; i++) sbuf[i] = (unsigned char)((i * 17u + 3u) & 0xffu);
        g_sig_ok = 0;
        g_sig_ptr = buf;
        g_sig_small = sbuf;
        raise(SIGUSR1);
        if (!g_sig_ok) {
            fprintf(stderr, "MT signal handler realloc failed or lost payload bytes\n");
            return 4;
        }
        printf("PASS: sig-realloc preserved payload\n");
        return 0;
    }

    /* Recycled dirty-slot calloc check across all small bins 1..32768 + >MAX_SMALL_SIZE up to 65536 */
    for (size_t sz = 1; sz <= 65536; sz = (sz < 64 ? sz + 1 : (sz < 4096 ? sz + 137 : sz + 2039))) {
        unsigned char *m = (unsigned char *)malloc(sz);
        if (!m) return 1;
        memset(m, 0xAA, sz);
        free(m);
        errno = EAGAIN;
        unsigned char *c = (unsigned char *)calloc(1, sz);
        if (!c || errno != EAGAIN) {
            fprintf(stderr, "calloc failed or clobbered errno at sz=%zu errno=%d\n", sz, errno);
            return 1;
        }
        for (size_t i = 0; i < sz; i++) {
            if (c[i] != 0) {
                fprintf(stderr, "dirty recycled calloc at sz=%zu i=%zu val=0x%02x\n", sz, i, c[i]);
                return 1;
            }
        }
        free(c);
    }

    /* Zero-size and 2^32 boundary checks */
    volatile size_t z0 = 0;
    volatile size_t huge_z = (size_t)-1;
    volatile size_t b32 = (size_t)1ULL << 32;
    void *z_a = calloc(z0, 64);
    void *z_b = calloc(64, z0);
    void *z_c = calloc(z0, huge_z);
    void *z_d = calloc(b32, z0);
    if (!z_a || !z_b || !z_c || !z_d) {
        fprintf(stderr, "zero-count calloc unexpectedly returned NULL\n");
        return 1;
    }
    free(z_a); free(z_b); free(z_c); free(z_d);

    /* Overflow check */
    errno = 0;
    volatile size_t huge = (size_t)-1;
    void *ov = calloc(huge, 2);
    if (ov != NULL || errno != ENOMEM) {
        fprintf(stderr, "overflow calloc failed: ov=%p errno=%d\n", ov, errno);
        return 1;
    }

    pthread_barrier_init(&bar, NULL, WORKERS);
    pthread_t th[WORKERS];
    for (int i = 0; i < WORKERS; i++) {
        if (pthread_create(&th[i], NULL, worker, (void *)(uintptr_t)(0x9e3779b9u * (unsigned)(i + 1))) != 0)
            return 1;
    }
    for (int i = 0; i < WORKERS; i++) {
        if (pthread_join(th[i], NULL) != 0) return 1;
    }
    pthread_barrier_destroy(&bar);
    printf("PASS: malloc_mt_and_calloc_gate verified\n");
    return 0;
}
"#,
    )
    .expect("probe_mt_calloc.c written");

    let st = Command::new("cc")
        .args([
            "-O2",
            "-fno-builtin",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pthread",
        ])
        .arg(&probe_c)
        .arg("-o")
        .arg(&probe_bin)
        .status()
        .expect("cc probe_mt_calloc");
    assert!(st.success(), "failed compiling probe_mt_calloc.c");

    if !lib.is_file() {
        let st = Command::new("cc")
            .args([
                "-std=c11",
                "-pthread",
                "-fsyntax-only",
                "-Wall",
                "-Wextra",
                "-Werror",
            ])
            .arg(root.join("tests/integration/fixture_fork_mt.c"))
            .status()
            .expect("cc syntax check");
        assert!(st.success(), "fixture_fork_mt.c syntax check failed");
        return;
    }

    // 1. fixture_fork_mt byte-identical output vs host glibc in strict + hardened:
    let fork_bin = tmp.join("fixture_fork_mt");
    let st = Command::new("cc")
        .args(["-O2", "-pthread"])
        .arg(root.join("tests/integration/fixture_fork_mt.c"))
        .arg("-o")
        .arg(&fork_bin)
        .status()
        .expect("cc fixture_fork_mt");
    assert!(st.success(), "failed compiling fixture_fork_mt.c");

    let host_fork = Command::new(&fork_bin)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("host fixture_fork_mt");
    assert!(host_fork.status.success(), "host fixture_fork_mt failed");

    for mode in ["strict", "hardened"] {
        let cand = Command::new(&fork_bin)
            .env("LD_PRELOAD", &lib)
            .env("FRANKENLIBC_MODE", mode)
            .output()
            .expect("candidate fixture_fork_mt");
        assert!(
            cand.status.success(),
            "fixture_fork_mt ({mode}) failed: {}",
            String::from_utf8_lossy(&cand.stderr)
        );
        assert_eq!(
            cand.stdout, host_fork.stdout,
            "fixture_fork_mt ({mode}) diverged from host glibc"
        );
    }

    for mode in ["strict", "hardened"] {
        for native_threads in ["0", "1"] {
            let out = Command::new(&probe_bin)
                .env("LD_PRELOAD", &lib)
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_THREAD_NATIVE", native_threads)
                .output()
                .expect("probe_mt_calloc run");
            assert!(
                out.status.success(),
                "probe_mt_calloc ({mode}, native={native_threads}) failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                String::from_utf8_lossy(&out.stdout)
                    .contains("PASS: malloc_mt_and_calloc_gate verified"),
                "missing PASS banner in {mode} (native={native_threads})"
            );

            let sig_out = Command::new(&probe_bin)
                .arg("sig-realloc")
                .env("LD_PRELOAD", &lib)
                .env("FRANKENLIBC_MODE", mode)
                .env("FRANKENLIBC_THREAD_NATIVE", native_threads)
                .output()
                .expect("probe_mt_calloc sig-realloc run");
            assert!(
                sig_out.status.success(),
                "probe_mt_calloc sig-realloc ({mode}, native={native_threads}) failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&sig_out.stdout),
                String::from_utf8_lossy(&sig_out.stderr)
            );
            assert!(
                String::from_utf8_lossy(&sig_out.stdout)
                    .contains("PASS: sig-realloc preserved payload"),
                "missing sig-realloc PASS banner in {mode} (native={native_threads})"
            );
        }
    }
}
