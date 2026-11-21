//! Integration gate test for `bd-rv2gv6`:
//! verifies `.init_array` `environ` preseeding (`dlopen(..., RTLD_LOCAL | RTLD_DEEPBIND)`
//! `MODE_UNRESOLVED` elimination), single-threaded parked static-slot `fmemopen`
//! reuse (`PARKED_STATIC_SLOT` + `TLS_FAST_MEM_READ.parked_slot`), frameless buffered
//! `fread` leaf fast path (`FixedMemCursor::try_take_buffered` + `raw_copy_under_128`),
//! parked-slot invisibility to `fflush(NULL)` and `EBADF` on double-`fclose`,
//! ST->MT eviction on `pthread_create`, live `LD_PRELOAD` + `RTLD_DEEPBIND`
//! `fmemopen_4k_fread_64b` lifecycle parity in `{strict, hardened}` modes, and
//! live paired `fmemopen_4k_fread_64b` latency against host glibc in the same process.

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
fn fmemopen_fread_fast_path_contracts_are_wired() {
    let root = workspace_root();
    let stdio_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/stdio_abi.rs"))
        .expect("stdio_abi.rs readable");
    let io_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/io_internal_abi.rs"))
        .expect("io_internal_abi.rs readable");
    let startup_src = fs::read_to_string(root.join("crates/frankenlibc-abi/src/startup_abi.rs"))
        .expect("startup_abi.rs readable");
    let core_file_src = fs::read_to_string(root.join("crates/frankenlibc-core/src/stdio/file.rs"))
        .expect("core stdio/file.rs readable");

    assert!(startup_src.contains("environ_uninitialized_for_init_array()"));
    assert!(io_src.contains("static PARKED_STATIC_SLOT: AtomicUsize = AtomicUsize::new(0);"));
    assert!(io_src.contains("pub(crate) unsafe fn park_static_slot_st("));
    assert!(io_src.contains("pub(crate) unsafe fn reoccupy_parked_static_slot_st("));
    assert!(stdio_src.contains("pub(crate) fn evict_parked_st_fmemopen_slot()"));
    assert!(stdio_src.contains("PARKED_GLOBAL_CURSOR"));
    assert!(stdio_src.contains("crate::string_abi::raw_copy_under_128("));
    assert!(core_file_src.contains("pub fn try_take_buffered(&mut self, len: usize)"));
}

#[test]
fn fmemopen_fread_live_preload_and_deepbind_gate_passes() {
    let root = workspace_root();
    let explicit_lib = std::env::var_os("FRANKENLIBC_FMEMOPEN_TEST_LIB").map(PathBuf::from);
    let lib = explicit_lib.unwrap_or_else(|| root.join("target/release/libfrankenlibc_abi.so"));
    assert!(
        lib.is_file(),
        "release libfrankenlibc_abi.so must exist for live fmemopen/fread gate: {}",
        lib.display()
    );

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!(
        "fl_fmemopen_fread_gate_{}_{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&tmp).expect("temp dir creatable");

    let probe_c = tmp.join("probe_fmemopen_fread.c");
    let probe_bin = tmp.join("probe_fmemopen_fread");
    fs::write(
        &probe_c,
        r#"#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t bench_fmemopen_4k_fread_64b_ns(
    FILE *(*fn_fmemopen)(void *, size_t, const char *),
    size_t (*fn_fread)(void *, size_t, size_t, FILE *),
    int (*fn_fclose)(FILE *),
    unsigned char *src,
    int iters
) {
    unsigned char out[64];
    volatile uint64_t sink = 0;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int r = 0; r < iters; ++r) {
        FILE *fp = fn_fmemopen(src, 4096, "rb");
        if (!fp) return UINT64_MAX;
        for (int i = 0; i < 64; ++i) {
            size_t got = fn_fread(out, 1, 64, fp);
            sink += (uint64_t)got + out[0];
        }
        if (fn_fclose(fp) != 0) return UINT64_MAX;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    (void)sink;
    return (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ull
         + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

static void *mt_reader_worker(void *arg) {
    const unsigned char *buf = (const unsigned char *)arg;
    unsigned char tmp[64];
    for (int r = 0; r < 64; ++r) {
        FILE *fp = fmemopen((void *)buf, 4096, "rb");
        if (!fp) return (void *)1;
        for (int i = 0; i < 64; ++i) {
            if (fread(tmp, 1, 64, fp) != 64) return (void *)2;
            if (memcmp(tmp, buf + (size_t)i * 64, 64) != 0) return (void *)3;
        }
        if (fread(tmp, 1, 64, fp) != 0 || !feof(fp)) return (void *)4;
        if (fclose(fp) != 0) return (void *)5;
    }
    return NULL;
}

static int verify_lifecycle_and_edges(
    FILE *(*fn_fmemopen)(void *, size_t, const char *),
    size_t (*fn_fread)(void *, size_t, size_t, FILE *),
    int (*fn_fclose)(FILE *),
    int (*fn_fflush)(FILE *),
    int (*fn_feof)(FILE *),
    long (*fn_ftell)(FILE *)
) {
    unsigned char src[4096];
    unsigned char out[128];
    for (size_t i = 0; i < sizeof(src); ++i) {
        src[i] = (unsigned char)((i * 131u + 17u) & 0xffu);
    }

    for (int rep = 0; rep < 256; ++rep) {
        src[0] = (unsigned char)(rep & 0xff);
        FILE *fp = fn_fmemopen(src, sizeof(src), "rb");
        if (!fp) return 10;
        for (int chunk = 0; chunk < 64; ++chunk) {
            size_t got = fn_fread(out, 1, 64, fp);
            if (got != 64) return 11;
            if (memcmp(out, src + (size_t)chunk * 64, 64) != 0) return 12;
        }
        if (fn_fread(out, 1, 64, fp) != 0) return 13;
        if (!fn_feof(fp)) return 14;
        if (fn_fclose(fp) != 0) return 15;
    }

    /* Parked-slot invisibility to fflush(NULL) + partial element + reopen state reset: */
    if (fn_fflush(NULL) != 0) return 20;

    unsigned char short_buf[130];
    for (size_t i = 0; i < sizeof(short_buf); ++i) {
        short_buf[i] = (unsigned char)(0xa5u ^ i);
    }
    FILE *p = fn_fmemopen(short_buf, sizeof(short_buf), "rb");
    if (!p) return 21;
    memset(out, 0, sizeof(out));
    if (fn_fread(out, 64, 2, p) != 2) return 22;
    if (memcmp(out, short_buf, 128) != 0) return 23;
    /* Only 2 bytes remain (< 64B element): must return 0, advance to 130, and set EOF. */
    if (fn_fread(out, 64, 1, p) != 0) return 24;
    if (!fn_feof(p)) return 25;
    if (fn_ftell(p) != 130L) return 26;
    if (fn_fclose(p) != 0) return 27;

    /* Next fmemopen reusing the parked slot must start with clean EOF=0 and pos=0: */
    FILE *p2 = fn_fmemopen(src, sizeof(src), "rb");
    if (!p2) return 28;
    if (fn_feof(p2) != 0 || fn_ftell(p2) != 0L) return 29;
    if (fn_fread(out, 1, 64, p2) != 64 || memcmp(out, src, 64) != 0) return 30;
    if (fn_fclose(p2) != 0) return 31;

    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "--deepbind") == 0) {
        int flags = RTLD_NOW | RTLD_LOCAL;
#ifdef RTLD_DEEPBIND
        flags |= RTLD_DEEPBIND;
#endif
        void *h = dlopen(argv[2], flags);
        if (!h) {
            fprintf(stderr, "dlopen failed: %s\n", dlerror());
            return 2;
        }
        typedef FILE *(*fmemopen_t)(void *, size_t, const char *);
        typedef size_t (*fread_t)(void *, size_t, size_t, FILE *);
        typedef int (*fclose_t)(FILE *);
        typedef int (*fflush_t)(FILE *);
        typedef int (*feof_t)(FILE *);
        typedef long (*ftell_t)(FILE *);
        fmemopen_t fn_fmemopen = (fmemopen_t)dlsym(h, "fmemopen");
        fread_t fn_fread = (fread_t)dlsym(h, "fread");
        fclose_t fn_fclose = (fclose_t)dlsym(h, "fclose");
        fflush_t fn_fflush = (fflush_t)dlsym(h, "fflush");
        feof_t fn_feof = (feof_t)dlsym(h, "feof");
        ftell_t fn_ftell = (ftell_t)dlsym(h, "ftell");
        if (!fn_fmemopen || !fn_fread || !fn_fclose || !fn_fflush || !fn_feof || !fn_ftell) {
            fprintf(stderr, "missing dlsym stdio export\n");
            return 3;
        }
        int rc = verify_lifecycle_and_edges(
            fn_fmemopen, fn_fread, fn_fclose, fn_fflush, fn_feof, fn_ftell
        );
        if (rc != 0) {
            fprintf(stderr, "deepbind lifecycle failed: %d\n", rc);
            return rc;
        }
        /* Live paired A/B latency check against host glibc in the same process: */
        unsigned char bench_src[4096];
        for (size_t i = 0; i < sizeof(bench_src); ++i) {
            bench_src[i] = (unsigned char)((i * 53u + 11u) & 0xffu);
        }
        /* Warmup both arms */
        if (bench_fmemopen_4k_fread_64b_ns(fmemopen, fread, fclose, bench_src, 64) == UINT64_MAX
            || bench_fmemopen_4k_fread_64b_ns(fn_fmemopen, fn_fread, fn_fclose, bench_src, 64) == UINT64_MAX) {
            fprintf(stderr, "deepbind warmup failed\n");
            return 60;
        }
        enum { TRIALS = 9, ITERS = 256 };
        double ratios[TRIALS];
        for (int t = 0; t < TRIALS; ++t) {
            uint64_t fl_ns = 0, gl_ns = 0;
            if ((t & 1) == 0) {
                fl_ns = bench_fmemopen_4k_fread_64b_ns(fn_fmemopen, fn_fread, fn_fclose, bench_src, ITERS);
                gl_ns = bench_fmemopen_4k_fread_64b_ns(fmemopen, fread, fclose, bench_src, ITERS);
            } else {
                gl_ns = bench_fmemopen_4k_fread_64b_ns(fmemopen, fread, fclose, bench_src, ITERS);
                fl_ns = bench_fmemopen_4k_fread_64b_ns(fn_fmemopen, fn_fread, fn_fclose, bench_src, ITERS);
            }
            if (fl_ns == UINT64_MAX || gl_ns == UINT64_MAX || gl_ns == 0) {
                fprintf(stderr, "deepbind paired timing error\n");
                return 61;
            }
            ratios[t] = (double)fl_ns / (double)gl_ns;
        }
        qsort(ratios, TRIALS, sizeof(double), cmp_double);
        double median_ratio = ratios[TRIALS / 2];
        if (median_ratio > 1.25) {
            fprintf(
                stderr,
                "deepbind fmemopen_4k_fread_64b perf regression: median fl/glibc ratio=%.3f > 1.25\n",
                median_ratio
            );
            return 62;
        }
        printf("PASS: deepbind fmemopen_4k_fread_64b verified (median fl/glibc=%.3f)\n", median_ratio);
        return 0;
    }

    int rc = verify_lifecycle_and_edges(fmemopen, fread, fclose, fflush, feof, ftell);
    if (rc != 0) {
        fprintf(stderr, "preload lifecycle failed: %d\n", rc);
        return rc;
    }

    /* Double-close of a parked ST fmemopen slot under FrankenLibC must return EOF + EBADF: */
    if (getenv("FRANKENLIBC_CHECK_DOUBLE_CLOSE") != NULL) {
        unsigned char buf[64] = {1, 2, 3, 4};
        FILE *fp = fmemopen(buf, sizeof(buf), "rb");
        volatile uintptr_t fp_raw = (uintptr_t)fp;
        if (!fp || fclose(fp) != 0) return 40;
        errno = 0;
        if (fclose((FILE *)fp_raw) != EOF || errno != EBADF) {
            fprintf(stderr, "double fclose expected EBADF, got errno=%d\n", errno);
            return 41;
        }
    }

    /* Transition ST -> MT after parked-slot activity and verify concurrent fmemopen+fread: */
    unsigned char shared[4096];
    for (size_t i = 0; i < sizeof(shared); ++i) {
        shared[i] = (unsigned char)((i * 73u + 9u) & 0xffu);
    }
    pthread_t th[2];
    for (int i = 0; i < 2; ++i) {
        if (pthread_create(&th[i], NULL, mt_reader_worker, shared) != 0) return 50;
    }
    for (int i = 0; i < 2; ++i) {
        void *res = NULL;
        if (pthread_join(th[i], &res) != 0 || res != NULL) return 51;
    }

    printf("PASS: preload fmemopen_4k_fread_64b verified\n");
    return 0;
}
"#,
    )
    .expect("probe C source written");

    let compile = Command::new("cc")
        .args(["-O2", "-pthread", "-Wall", "-Werror"])
        .arg(&probe_c)
        .arg("-ldl")
        .arg("-o")
        .arg(&probe_bin)
        .status()
        .expect("cc compile probe_fmemopen_fread");
    assert!(compile.success(), "probe_fmemopen_fread.c must compile");

    let host = Command::new(&probe_bin)
        .env_remove("LD_PRELOAD")
        .env_remove("FRANKENLIBC_CHECK_DOUBLE_CLOSE")
        .output()
        .expect("host probe_fmemopen_fread");
    assert!(
        host.status.success(),
        "host probe_fmemopen_fread failed: {}",
        String::from_utf8_lossy(&host.stderr)
    );

    for (mode, native_threads) in [
        ("strict", false),
        ("hardened", false),
        ("strict", true),
        ("hardened", true),
    ] {
        let mut cmd = Command::new(&probe_bin);
        cmd.env("LD_PRELOAD", &lib)
            .env("FRANKENLIBC_MODE", mode)
            .env("FRANKENLIBC_CHECK_DOUBLE_CLOSE", "1");
        if native_threads {
            cmd.env("FRANKENLIBC_THREAD_NATIVE", "1")
                .env_remove("FRANKENLIBC_THREAD_DELEGATE");
        } else {
            cmd.env_remove("FRANKENLIBC_THREAD_NATIVE");
        }
        let preload = cmd.output().expect("preload probe_fmemopen_fread");
        assert!(
            preload.status.success(),
            "preload probe_fmemopen_fread ({mode}, native={native_threads}) failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&preload.stdout),
            String::from_utf8_lossy(&preload.stderr)
        );
        assert!(
            String::from_utf8_lossy(&preload.stdout)
                .contains("PASS: preload fmemopen_4k_fread_64b verified"),
            "missing preload PASS banner in ({mode}, native={native_threads})"
        );
    }

    let deepbind = Command::new(&probe_bin)
        .arg("--deepbind")
        .arg(&lib)
        .env_remove("LD_PRELOAD")
        .env_remove("FRANKENLIBC_MODE")
        .env("GLIBC_TUNABLES", "glibc.rtld.optional_static_tls=16384")
        .output()
        .expect("deepbind probe_fmemopen_fread");
    assert!(
        deepbind.status.success(),
        "deepbind probe_fmemopen_fread failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&deepbind.stdout),
        String::from_utf8_lossy(&deepbind.stderr)
    );
    assert!(
        String::from_utf8_lossy(&deepbind.stdout)
            .contains("PASS: deepbind fmemopen_4k_fread_64b verified"),
        "missing deepbind PASS banner"
    );
}
