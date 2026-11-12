#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Wave 4 E2E verification (`bd-reality-202609-lx578q.6.4` & `.6.5`):
//! 1. Release `.dynsym` exports `_IO_2_1_stdin_@@GLIBC_2.2.5`,
//!    `_IO_2_1_stdout_@@GLIBC_2.2.5`, and `_IO_2_1_stderr_@@GLIBC_2.2.5` as
//!    224-byte `OBJECT` symbols.
//! 2. Both `-fno-pie -no-pie` (`R_X86_64_COPY`) and `-fPIE -pie`
//!    (`R_X86_64_GLOB_DAT`) C fixtures bind `_IO_2_1_std*_` to
//!    `libfrankenlibc_abi.so` (`LD_DEBUG=bindings`) and execute `putc`,
//!    `fwrite`, `fflush`, `fileno`, and `freopen` under `strict` and
//!    `hardened` modes.
//! 3. `libgcc_s`-denied multi-frame C++ RAII (`struct CppGuard`) + Rust RAII
//!    (`impl Drop for RustGuard`) + POSIX `pthread_cleanup_push` thread
//!    cancellation and `pthread_exit` run destructors in exact LIFO order with
//!    zero `libgcc_s.so.1` / `libunwind` mapped in `/proc/self/maps` and emit
//!    `frankenlibc.owned_unwind.v1` JSONL trace events.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn find_warm_rch_target_dir(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(".rch-target-") {
            continue;
        }
        let candidate = entry.path().join("release/libfrankenlibc_abi.so");
        if let Ok(meta) = std::fs::metadata(&candidate)
            && meta.is_file()
        {
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(prev, _)| mtime > *prev) {
                best = Some((mtime, entry.path()));
            }
        }
    }
    best.map(|(_, p)| p)
}

fn find_release_abi_so(root: &Path) -> PathBuf {
    static BUILT_SO: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    if let Ok(explicit) = std::env::var("FRANKENLIBC_RELEASE_SO") {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return p;
        }
    }
    BUILT_SO
        .get_or_init(|| {
            let target_dir = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .or_else(|| find_warm_rch_target_dir(root))
                .unwrap_or_else(|| root.join("target"));
            let status = Command::new("cargo")
                .current_dir(root)
                .arg("build")
                .arg("--target-dir")
                .arg(&target_dir)
                .args(["-p", "frankenlibc-abi", "--release"])
                .status()
                .expect("spawn cargo build --release -p frankenlibc-abi");
            assert!(
                status.success(),
                "cargo build --release -p frankenlibc-abi failed"
            );
            let so = target_dir.join("release/libfrankenlibc_abi.so");
            assert!(
                so.is_file(),
                "missing release libfrankenlibc_abi.so at {}",
                so.display()
            );
            so
        })
        .clone()
}

#[test]
fn release_dynsym_exports_224_byte_io_2_1_objects_at_glibc_2_2_5() {
    let root = workspace_root();
    let so_path = find_release_abi_so(&root);
    let output = Command::new("readelf")
        .args(["--dyn-syms", "--wide"])
        .arg(&so_path)
        .output()
        .expect("readelf --dyn-syms --wide should run");
    assert!(output.status.success(), "readelf failed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    for sym in ["_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"] {
        let expected_ver = format!("{sym}@@GLIBC_2.2.5");
        let matched = stdout
            .lines()
            .find(|line| line.split_whitespace().last() == Some(expected_ver.as_str()))
            .unwrap_or_else(|| {
                panic!(
                    "missing `{expected_ver}` in release .dynsym of {}",
                    so_path.display()
                )
            });
        let cols: Vec<&str> = matched.split_whitespace().collect();
        // Format: Num: Value Size Type Bind Vis Ndx Name
        assert!(cols.len() >= 8, "unexpected readelf row: {matched}");
        let size_str = cols[2];
        let size = if let Some(hex) = size_str.strip_prefix("0x") {
            usize::from_str_radix(hex, 16).expect("hex size")
        } else {
            size_str.parse::<usize>().expect("decimal size")
        };
        assert_eq!(
            size, 224,
            "{expected_ver} must have sizeof(_IO_FILE_plus) == 224, got row: {matched}"
        );
        assert_eq!(
            cols[3], "OBJECT",
            "{expected_ver} must be STT_OBJECT: {matched}"
        );
        assert_eq!(
            cols[4], "GLOBAL",
            "{expected_ver} must be STB_GLOBAL: {matched}"
        );
        assert_ne!(cols[6], "UND", "{expected_ver} must be defined: {matched}");
    }
}

#[test]
fn copy_reloc_and_got_stdio_c_fixtures_bind_and_work_in_strict_and_hardened() {
    let root = workspace_root();
    let so_path = find_release_abi_so(&root);
    let out_dir = root.join("target/wave4_e2e_stdio");
    std::fs::create_dir_all(&out_dir).expect("create wave4_e2e_stdio dir");

    let c_src = out_dir.join("probe_io_2_1_copy_and_got.c");
    std::fs::write(
        &c_src,
        r#"#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern FILE _IO_2_1_stdin_;
extern FILE _IO_2_1_stdout_;
extern FILE _IO_2_1_stderr_;

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *reopen_path = argv[1];

    if (stdin != &_IO_2_1_stdin_ || stdout != &_IO_2_1_stdout_ || stderr != &_IO_2_1_stderr_) {
        fprintf(stderr, "initial pointer mismatch: stdin=%#zx/%#zx stdout=%#zx/%#zx stderr=%#zx/%#zx\n",
                (size_t)(uintptr_t)stdin, (size_t)(uintptr_t)&_IO_2_1_stdin_,
                (size_t)(uintptr_t)stdout, (size_t)(uintptr_t)&_IO_2_1_stdout_,
                (size_t)(uintptr_t)stderr, (size_t)(uintptr_t)&_IO_2_1_stderr_);
        return 3;
    }
    if (fileno(&_IO_2_1_stdin_) != 0 || fileno(&_IO_2_1_stdout_) != 1 || fileno(&_IO_2_1_stderr_) != 2) {
        return 4;
    }
    if (putc('A', &_IO_2_1_stdout_) != 'A') return 5;
    if (fwrite("-BC", 1, 3, &_IO_2_1_stdout_) != 3) return 6;
    if (fflush(&_IO_2_1_stdout_) != 0) return 7;

    FILE *reopened = freopen(reopen_path, "w", &_IO_2_1_stdout_);
    if (reopened != &_IO_2_1_stdout_) return 8;
    if (fwrite("reopened-ok\n", 1, 12, stdout) != 12) return 9;
    if (fflush(&_IO_2_1_stdout_) != 0) return 10;
    return 0;
}
"#,
    )
    .expect("write C probe");

    for (style, flags, expected_reloc) in [
        ("no_pie", &["-fno-pie", "-no-pie"][..], "R_X86_64_COPY"),
        ("pic_pie", &["-fPIC", "-pie"][..], "R_X86_64_GLOB_DAT"),
    ] {
        let bin = out_dir.join(format!("probe_io_2_1_{style}"));
        let mut cc = Command::new("cc");
        cc.args(["-O2", "-fno-builtin", "-Wall", "-Wextra", "-Werror"])
            .args(flags)
            .arg(&c_src)
            .arg("-o")
            .arg(&bin);
        let status = cc.status().expect("compile C probe");
        assert!(status.success(), "cc failed for {style}");

        let relocs = Command::new("readelf")
            .args(["-r", "--wide"])
            .arg(&bin)
            .output()
            .expect("readelf -r");
        let reloc_text = String::from_utf8_lossy(&relocs.stdout);
        assert!(
            reloc_text
                .lines()
                .any(|l| l.contains(expected_reloc) && l.contains("_IO_2_1_stdout_")),
            "{style} binary must emit {expected_reloc} for _IO_2_1_stdout_, got:\n{reloc_text}"
        );

        for mode in ["strict", "hardened"] {
            let reopen_file = out_dir.join(format!("reopened_{style}_{mode}.txt"));
            let ld_debug_prefix = out_dir.join(format!("ld_debug_{style}_{mode}.log"));
            let output = Command::new(&bin)
                .arg(&reopen_file)
                .env("LD_PRELOAD", &so_path)
                .env("FRANKENLIBC_MODE", mode)
                .env("LD_DEBUG", "bindings")
                .env("LD_DEBUG_OUTPUT", &ld_debug_prefix)
                .output()
                .expect("run C probe under LD_PRELOAD");
            assert!(
                output.status.success(),
                "{style}/{mode} probe failed ({:?}): stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                &output.stdout, b"A-BC",
                "{style}/{mode} pre-freopen stdout mismatch"
            );
            let reopened_bytes = std::fs::read_to_string(&reopen_file).expect("read reopened file");
            assert_eq!(reopened_bytes, "reopened-ok\n");

            // LD_DEBUG_OUTPUT writes `<prefix>.<pid>`; locate the generated log.
            let prefix_name = ld_debug_prefix
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let log_file = std::fs::read_dir(&out_dir)
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with(&prefix_name)
                })
                .expect("LD_DEBUG bindings log must exist");
            let bindings = std::fs::read_to_string(&log_file).expect("read LD_DEBUG log");
            for sym in ["_IO_2_1_stdin_", "_IO_2_1_stdout_", "_IO_2_1_stderr_"] {
                // Verify normal lookup binds to libfrankenlibc_abi.so (in copy-reloc
                // mode, ld.so binds the executable to libfrankenlibc_abi.so to copy
                // initial bytes and binds DSOs to the main binary; it must NEVER bind
                // _IO_2_1_std*_ to host libc.so.6!).
                let sym_lines: Vec<&str> = bindings
                    .lines()
                    .filter(|l| {
                        l.contains("binding file")
                            && (l.contains(&format!("`{sym}'")) || l.contains(&format!("'{sym}'")))
                    })
                    .collect();
                assert!(
                    !sym_lines.is_empty(),
                    "{style}/{mode}: expected LD_DEBUG binding lines for {sym}"
                );
                assert!(
                    sym_lines.iter().any(|l| {
                        l.split_once(" to ")
                            .is_some_and(|(_, target)| target.contains("libfrankenlibc_abi.so"))
                    }),
                    "{style}/{mode}: {sym} never bound to libfrankenlibc_abi.so:\n{}",
                    sym_lines.join("\n")
                );
                assert!(
                    sym_lines.iter().all(|l| {
                        l.split_once(" to ")
                            .is_none_or(|(_, target)| !target.contains("libc.so.6"))
                    }),
                    "{style}/{mode}: {sym} unexpectedly bound to host libc.so.6:\n{}",
                    sym_lines.join("\n")
                );
            }
        }
    }
}

#[test]
fn libgcc_denied_cpp_rust_and_posix_cleanup_destructors_run_lifo_on_exit_and_cancel() {
    let root = workspace_root();
    let out_dir = root.join("target/wave4_e2e_unwind");
    std::fs::create_dir_all(&out_dir).expect("create wave4_e2e_unwind dir");

    // Build owned-unwind-stub libfrankenlibc_abi.so into an isolated target dir
    // (or reuse FRANKENLIBC_STANDALONE_UNWIND_SO if prebuilt by caller).
    let standalone_so = if let Ok(explicit) = std::env::var("FRANKENLIBC_STANDALONE_UNWIND_SO") {
        let p = PathBuf::from(explicit);
        assert!(
            p.is_file(),
            "FRANKENLIBC_STANDALONE_UNWIND_SO missing: {}",
            p.display()
        );
        p
    } else {
        let standalone_target = root.join("target/wave4_standalone_unwind");
        let status = Command::new("cargo")
            .current_dir(&root)
            .env("CARGO_TARGET_DIR", &standalone_target)
            .env("CARGO_PROFILE_RELEASE_PANIC", "abort")
            .args([
                "build",
                "-p",
                "frankenlibc-abi",
                "--release",
                "--features",
                "owned-unwind-stub",
            ])
            .status()
            .expect("build owned-unwind-stub libfrankenlibc_abi.so");
        assert!(status.success(), "owned-unwind-stub build failed");
        standalone_target.join("release/libfrankenlibc_abi.so")
    };

    let dyn_out = Command::new("readelf")
        .args(["-d", "--wide"])
        .arg(&standalone_so)
        .output()
        .expect("readelf -d standalone_so");
    let dyn_text = String::from_utf8_lossy(&dyn_out.stdout);
    assert!(
        !dyn_text.contains("libgcc_s") && !dyn_text.contains("libunwind"),
        "standalone_so must have zero libgcc_s/libunwind DT_NEEDED:\n{dyn_text}"
    );

    let dyn_syms_out = Command::new("readelf")
        .args(["--dyn-syms", "--wide"])
        .arg(&standalone_so)
        .output()
        .expect("readelf --dyn-syms standalone_so");
    let dyn_syms_text = String::from_utf8_lossy(&dyn_syms_out.stdout);
    assert!(
        dyn_syms_text.contains("_Unwind_ForcedUnwind@@GCC_3.0")
            && dyn_syms_text.contains("_Unwind_GetCFA@@GCC_3.3"),
        "standalone_so must export versioned _Unwind_ForcedUnwind@@GCC_3.0 and _Unwind_GetCFA@@GCC_3.3:\n{dyn_syms_text}"
    );

    // 1. Build zero-TLS LD_PRELOAD guard DSO that fails closed (_exit(99)) if
    //    anything attempts to dlopen/__libc_dlopen_mode libgcc_s* or libunwind*.
    //    (Avoids LD_AUDIT secondary link-map TLS_STATIC_SURPLUS exhaustion under -enable-tlsdesc.)
    let audit_c = out_dir.join("deny_libgcc_dlopen.c");
    let audit_so = out_dir.join("libdeny_libgcc_dlopen.so");
    std::fs::write(
        &audit_c,
        r#"#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

typedef void *(*dlopen_fn)(const char *, int);

void *dlopen(const char *filename, int flags) {
    if (filename != NULL &&
        (strstr(filename, "libgcc_s") != NULL || strstr(filename, "libunwind") != NULL)) {
        return NULL;
    }
    dlopen_fn next = (dlopen_fn)dlsym(RTLD_NEXT, "dlopen");
    return next ? next(filename, flags) : NULL;
}

void *__libc_dlopen_mode(const char *filename, int mode) {
    if (filename != NULL &&
        (strstr(filename, "libgcc_s") != NULL || strstr(filename, "libunwind") != NULL)) {
        return NULL;
    }
    dlopen_fn next = (dlopen_fn)dlsym(RTLD_NEXT, "__libc_dlopen_mode");
    return next ? next(filename, mode) : NULL;
}
"#,
    )
    .expect("write deny_libgcc_dlopen C");
    let status = Command::new("cc")
        .args(["-O2", "-shared", "-fPIC"])
        .arg(&audit_c)
        .arg("-ldl")
        .arg("-o")
        .arg(&audit_so)
        .status()
        .expect("compile deny_libgcc_dlopen .so");
    assert!(status.success(), "compile deny_libgcc_dlopen .so failed");

    // 2. Build a #![no_std] Rust staticlib compiled with -C panic=unwind -C force-unwind-tables=yes
    //    whose `Drop` guard records into an event array before forced unwind continues!
    let rust_src = out_dir.join("rust_raii_guard.rs");
    let rust_lib = out_dir.join("librust_raii_guard.a");
    std::fs::write(
        &rust_src,
        r#"#![no_std]
#![allow(internal_features)]
#![feature(lang_items)]

use core::ffi::c_int;

unsafe extern "C-unwind" {
    fn record_unwind_step(tag: c_int);
    fn inner_c_cleanup_and_trigger(mode: c_int);
    fn __gxx_personality_v0(
        version: c_int,
        actions: c_int,
        exception_class: u64,
        exception_object: *mut u8,
        context: *mut u8,
    ) -> c_int;
}

struct RustDropGuard(c_int);

impl Drop for RustDropGuard {
    fn drop(&mut self) {
        unsafe { record_unwind_step(self.0) };
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C-unwind" fn rust_raii_frame(mode: c_int) {
    let guard = RustDropGuard(202);
    core::hint::black_box(&guard);
    unsafe { inner_c_cleanup_and_trigger(mode) };
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[lang = "eh_personality"]
unsafe extern "C" fn eh_personality(
    version: c_int,
    actions: c_int,
    exception_class: u64,
    exception_object: *mut u8,
    context: *mut u8,
) -> c_int {
    unsafe { __gxx_personality_v0(version, actions, exception_class, exception_object, context) }
}
"#,
    )
    .expect("write rust_raii_guard.rs");
    let status = Command::new("rustc")
        .args([
            "--edition=2024",
            "--crate-type=staticlib",
            "-O",
            "-C",
            "panic=unwind",
            "-C",
            "force-unwind-tables=yes",
            "-C",
            "relocation-model=pic",
        ])
        .arg(&rust_src)
        .arg("-o")
        .arg(&rust_lib)
        .status()
        .expect("compile rust_raii_guard.rs");
    assert!(status.success(), "rustc staticlib failed");

    // 3. Build plain-C inner POSIX cleanup object WITHOUT `-fexceptions` so
    //    `pthread_cleanup_push` expands to `__sigsetjmp` + `__pthread_register_cancel`
    //    + `__pthread_unwind_next`, exercising `native_unwind_stop` CFA matching and
    //    forced-unwind restart alongside C++ and Rust RAII landing pads!
    let inner_c_src = out_dir.join("inner_c_cleanup.c");
    let inner_c_obj = out_dir.join("inner_c_cleanup.o");
    std::fs::write(
        &inner_c_src,
        r#"#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

extern void record_unwind_step(int tag);
extern void check_maps_clean(void);
extern volatile int g_child_ready;

static void posix_c_cleanup(void *arg) {
    int tag = (int)(intptr_t)arg;
    record_unwind_step(tag);
}

__attribute__((noinline)) void inner_c_cleanup_and_trigger(int mode) {
    check_maps_clean();
    pthread_cleanup_push(posix_c_cleanup, (void *)(intptr_t)303);
    if (mode == 0) {
        pthread_exit((void *)0x42);
    } else {
        g_child_ready = 1;
        for (;;) {
            pthread_testcancel();
            usleep(1000);
        }
    }
    pthread_cleanup_pop(0);
}
"#,
    )
    .expect("write inner_c_cleanup.c");
    let status = Command::new("cc")
        .args([
            "-O2",
            "-fPIC",
            "-fasynchronous-unwind-tables",
            "-fno-exceptions",
            "-c",
        ])
        .arg(&inner_c_src)
        .arg("-o")
        .arg(&inner_c_obj)
        .status()
        .expect("compile inner_c_cleanup.c");
    assert!(status.success(), "cc inner_c_cleanup.c failed");

    // 4. Build shared C++ + POSIX cleanup fixture WITHOUT libgcc_s (`-nodefaultlibs`, static libstdc++).
    let cpp_src = out_dir.join("raii_cancel_fixture.cpp");
    let fixture_so = out_dir.join("libraii_cancel_fixture.so");
    std::fs::write(
        &cpp_src,
        r#"#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int g_events[16];
static int g_event_count = 0;
extern "C" {
volatile int g_child_ready = 0;
}
static volatile int g_maps_has_libgcc = 0;

extern "C" void record_unwind_step(int tag) {
    if (g_event_count < 16) {
        g_events[g_event_count++] = tag;
    }
}

extern "C" void rust_raii_frame(int mode);

extern "C" void check_maps_clean(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        g_maps_has_libgcc = 1;
        return;
    }
    char buf[16384];
    ssize_t total = 0;
    while (total < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + total, sizeof(buf) - 1 - (size_t)total);
        if (n <= 0) break;
        total += n;
    }
    close(fd);
    buf[total] = '\0';
    if (strstr(buf, "libgcc_s") != NULL || strstr(buf, "libunwind") != NULL) {
        g_maps_has_libgcc = 1;
    }
}

static void posix_c_cleanup(void *arg) {
    int tag = (int)(intptr_t)arg;
    record_unwind_step(tag);
}

struct CppRaiiGuard {
    int tag;
    explicit CppRaiiGuard(int t) : tag(t) {}
    ~CppRaiiGuard() { record_unwind_step(tag); }
};

__attribute__((noinline)) static void cpp_outer_frame(int mode) {
    CppRaiiGuard cpp_guard(101);
    asm volatile("" : : "r"(&cpp_guard) : "memory");
    rust_raii_frame(mode);
}

static void *worker_entry(void *arg) {
    int mode = (int)(intptr_t)arg;
    pthread_cleanup_push(posix_c_cleanup, (void *)(intptr_t)404);
    cpp_outer_frame(mode);
    pthread_cleanup_pop(0);
    return NULL;
}

extern "C" int run_forced_unwind_case(int mode, int *out_events, int *out_count) {
    g_event_count = 0;
    g_child_ready = 0;
    g_maps_has_libgcc = 0;

    // Verify LD_AUDIT actively denies explicit dlopen("libgcc_s.so.1").
    void *probe = dlopen("libgcc_s.so.1", RTLD_NOW);
    if (probe != NULL) {
        dlclose(probe);
        return 90;
    }

    // Verify pthread_create and _Unwind_Resume bind to libfrankenlibc_abi.so.
    Dl_info p_info, u_info;
    void *u_resume = dlsym(RTLD_DEFAULT, "_Unwind_Resume");
    if (u_resume == NULL ||
        dladdr((void *)&pthread_create, &p_info) == 0 ||
        dladdr(u_resume, &u_info) == 0 ||
        p_info.dli_fname == NULL || u_info.dli_fname == NULL ||
        strstr(p_info.dli_fname, "libfrankenlibc_abi.so") == NULL ||
        strstr(u_info.dli_fname, "libfrankenlibc_abi.so") == NULL) {
        return 89;
    }

    pthread_t th;
    if (pthread_create(&th, NULL, worker_entry, (void *)(intptr_t)mode) != 0) {
        return 91;
    }
    if (mode == 1) {
        while (!g_child_ready) {
            usleep(1000);
        }
        if (pthread_cancel(th) != 0) {
            return 92;
        }
    }
    void *retval = NULL;
    if (pthread_join(th, &retval) != 0) {
        return 93;
    }
    check_maps_clean();
    if (g_maps_has_libgcc) {
        return 94;
    }
    if (mode == 0 && retval != (void *)0x42) {
        return 95;
    }
    if (mode == 1 && retval != PTHREAD_CANCELED) {
        return 96;
    }
    *out_count = g_event_count;
    for (int i = 0; i < g_event_count; ++i) {
        out_events[i] = g_events[i];
    }
    return 0;
}
"#,
    )
    .expect("write C++ fixture");

    let status = Command::new("g++")
        .args(["-O2", "-fPIC", "-fexceptions", "-shared", "-nodefaultlibs"])
        .arg(&cpp_src)
        .arg(&inner_c_obj)
        .arg(&rust_lib)
        .args([
            "-Wl,-Bstatic",
            "-lstdc++",
            "-Wl,-Bdynamic",
            "-lc",
            "-lm",
            "-ldl",
            "-Wl,--exclude-libs,ALL",
            "-Wl,--allow-shlib-undefined",
            "-Wl,--unresolved-symbols=ignore-all",
            "-o",
        ])
        .arg(&fixture_so)
        .status()
        .expect("compile libraii_cancel_fixture.so");
    assert!(status.success(), "g++ shared fixture failed");

    // Verify ldd on fixture_so has ZERO libgcc_s / libunwind.
    let ldd_out = Command::new("ldd")
        .arg(&fixture_so)
        .output()
        .expect("ldd fixture_so");
    let ldd_text = String::from_utf8_lossy(&ldd_out.stdout);
    assert!(
        !ldd_text.contains("libgcc_s") && !ldd_text.contains("libunwind"),
        "fixture_so must not depend on libgcc_s or libunwind:\n{ldd_text}"
    );

    // 4. Build a minimal plain-C runner (`-nodefaultlibs -lc -ldl`) so the host runner binary
    //    itself has ZERO DT_NEEDED on libgcc_s.so.1!
    let runner_c = out_dir.join("raii_cancel_runner.c");
    let runner_bin = out_dir.join("raii_cancel_runner");
    std::fs::write(
        &runner_c,
        r#"#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*run_case_fn)(int, int *, int *);

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "--verify-deny-libgcc") == 0) {
        void *blocked = dlopen("libgcc_s.so.1", RTLD_LAZY);
        return blocked == NULL ? 99 : 0;
    }
    void *fx = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (fx == NULL) {
        fprintf(stderr, "dlopen fixture failed: %s\n", dlerror());
        return 4;
    }
    run_case_fn run_case = (run_case_fn)dlsym(fx, "run_forced_unwind_case");
    if (run_case == NULL) {
        fprintf(stderr, "dlsym run_forced_unwind_case failed\n");
        return 5;
    }
    for (int mode = 0; mode <= 1; ++mode) {
        int events[16] = {0};
        int count = 0;
        int rc = run_case(mode, events, &count);
        if (rc != 0) {
            fprintf(stderr, "mode %d failed with rc=%d\n", mode, rc);
            return 10 + rc;
        }
        printf("mode=%d count=%d:", mode, count);
        for (int i = 0; i < count; ++i) {
            printf(" %d", events[i]);
        }
        printf("\n");
        fflush(stdout);
    }
    fflush(stdout);
    return 0;
}
"#,
    )
    .expect("write runner C");
    let status = Command::new("cc")
        .args(["-O2"])
        .arg(&runner_c)
        .args(["-ldl", "-o"])
        .arg(&runner_bin)
        .status()
        .expect("compile runner C");
    assert!(status.success(), "compile runner C failed");

    let runner_dyn = Command::new("readelf")
        .args(["-d", "--wide"])
        .arg(&runner_bin)
        .output()
        .expect("readelf -d runner_bin");
    let runner_dyn_text = String::from_utf8_lossy(&runner_dyn.stdout);
    assert!(
        !runner_dyn_text.contains("libgcc_s") && !runner_dyn_text.contains("libunwind"),
        "runner_bin must have zero libgcc_s/libunwind DT_NEEDED:\n{runner_dyn_text}"
    );

    let preload_chain = format!("{}:{}", audit_so.display(), standalone_so.display());

    // Negative control: verify the preload guard immediately terminates with exit 99
    // if anything attempts to dlopen("libgcc_s.so.1").
    let neg_out = Command::new(&runner_bin)
        .arg("--verify-deny-libgcc")
        .env("LD_PRELOAD", &preload_chain)
        .output()
        .expect("execute --verify-deny-libgcc negative control");
    assert_eq!(
        neg_out.status.code(),
        Some(99),
        "dlopen(libgcc_s.so.1) must fail closed with exit 99, got {:?}, stderr={}",
        neg_out.status.code(),
        String::from_utf8_lossy(&neg_out.stderr)
    );

    let jsonl_path = out_dir.join("owned_unwind.jsonl");
    let _ = std::fs::write(&jsonl_path, "");
    let run_out = Command::new(&runner_bin)
        .arg(&fixture_so)
        .env("LD_PRELOAD", &preload_chain)
        .env("FRANKENLIBC_THREAD_NATIVE", "1")
        .env("FRANKENLIBC_OWNED_UNWIND_JSONL", &jsonl_path)
        .env("RUST_BACKTRACE", "full")
        .output()
        .expect("execute raii_cancel_runner");
    let jsonl_dump = std::fs::read_to_string(&jsonl_path).unwrap_or_default();
    assert!(
        run_out.status.success(),
        "raii_cancel_runner failed ({:?}):\nstdout:\n{}\nstderr:\n{}\njsonl:\n{}",
        run_out.status.code(),
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr),
        jsonl_dump
    );

    let stdout = String::from_utf8_lossy(&run_out.stdout);
    // Expected LIFO order:
    // 1. inner_c_cleanup_and_trigger's pthread_cleanup_push (303)
    // 2. rust_raii_frame's RustDropGuard (202)
    // 3. cpp_outer_frame's CppRaiiGuard (101)
    // 4. worker_entry's outer pthread_cleanup_push (404)
    assert!(
        stdout.contains("mode=0 count=4: 303 202 101 404"),
        "pthread_exit LIFO destructor order mismatch, got:\n{stdout}"
    );
    assert!(
        stdout.contains("mode=1 count=4: 303 202 101 404"),
        "pthread_cancel LIFO destructor order mismatch, got:\n{stdout}"
    );

    let jsonl = std::fs::read_to_string(&jsonl_path).expect("read owned_unwind.jsonl");
    let parsed: Vec<Value> = jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("valid JSONL line"))
        .collect();
    assert!(
        !parsed.is_empty(),
        "FRANKENLIBC_OWNED_UNWIND_JSONL must contain forced-unwind trace events"
    );
    for row in &parsed {
        assert_eq!(row["schema_version"], "frankenlibc.owned_unwind.v1");
    }
    assert!(
        parsed.iter().any(|r| r["event"] == "forced_unwind_stop"),
        "expected forced_unwind_stop event in JSONL"
    );
    assert!(
        parsed
            .iter()
            .any(|r| r["event"] == "forced_unwind_install_cleanup"),
        "expected forced_unwind_install_cleanup event in JSONL"
    );
}

#[test]
fn wave7_tls_destructors_no_pie_environ_closed_fflush_and_memchr_usize_max_work() {
    let root = workspace_root();
    let so_path = find_release_abi_so(&root);
    let out_dir = root.join("target/wave7_e2e_probes");
    std::fs::create_dir_all(&out_dir).expect("create wave7_e2e_probes dir");

    let c_src = out_dir.join("wave7_probe.c");
    std::fs::write(
        &c_src,
        r#"#define _GNU_SOURCE 1
#include <errno.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

extern char **environ;
extern char **_environ;
extern char **__environ;

static pthread_key_t g_key_round1;
static pthread_key_t g_key_round2;
static volatile int g_dtor_ok = 0;

static void key_dtor_round2(void *val) {
    if ((uintptr_t)val != 0x22) return;
    // Exercise ABI TLS buffers DURING late pthread_key_create destructor round!
    const char *err = strerror(ENOENT);
    if (err == NULL || strlen(err) == 0) return;

    char fmt_buf[64];
    int n = snprintf(fmt_buf, sizeof(fmt_buf), "dtor-%d", 42);
    if (n != 7 || strcmp(fmt_buf, "dtor-42") != 0) return;

    time_t epoch = 0;
    struct tm *gmt = gmtime(&epoch);
    if (gmt == NULL || gmt->tm_year != 70) return;

    char mem_payload[] = "line-one\nline-two\n";
    FILE *mfp = fmemopen(mem_payload, strlen(mem_payload), "r");
    if (mfp == NULL) return;
    char line[32] = {0};
    if (fgets(line, sizeof(line), mfp) == NULL || strcmp(line, "line-one\n") != 0) {
        fclose(mfp);
        return;
    }
    fclose(mfp);

    typedef struct pollfd *(*rpc_pollfd_fn)(void);
    rpc_pollfd_fn get_pollfd = (rpc_pollfd_fn)dlsym(RTLD_DEFAULT, "__rpc_thread_svc_pollfd");
    if (get_pollfd != NULL) {
        struct pollfd *pfd = get_pollfd();
        if (pfd == NULL) return;
        pfd[0].events = POLLIN;
    }

    __sync_fetch_and_add(&g_dtor_ok, 1);
}

static void key_dtor_round1(void *val) {
    if ((uintptr_t)val != 0x11) return;
    // Re-arm round 2 key during round 1 destructor to test multi-round TLS survival!
    if (pthread_setspecific(g_key_round2, (void *)(uintptr_t)0x22) != 0) return;
    __sync_fetch_and_add(&g_dtor_ok, 10);
}

static void *tls_dtor_worker(void *arg) {
    (void)arg;
    // Pre-warm TLS cells on this worker before exit so destructors hit already-initialized cells
    // AND also exercise post-exit reclamation.
    (void)strerror(EINVAL);
    time_t now = 12345;
    (void)gmtime(&now);
    if (pthread_setspecific(g_key_round1, (void *)(uintptr_t)0x11) != 0) {
        return (void *)(uintptr_t)1;
    }
    return NULL;
}

int main(void) {
    // 1. memchr / strnlen / strncmp / strnstr / wcsnlen / wmemchr with SIZE_MAX must not
    //    panic, overflow, or be denied by barrier admissibility checks.
    char hay[32] = "abcdefXghijk";
    void *found = memchr(hay, 'X', (size_t)-1);
    if (found != (void *)(hay + 6)) {
        fprintf(stderr, "memchr SIZE_MAX failed: got %p expected %p\n", found, (void *)(hay + 6));
        return 11;
    }
    if (strnlen(hay, (size_t)-1) != 12) {
        fprintf(stderr, "strnlen SIZE_MAX failed\n");
        return 110;
    }
    if (strncmp("abc", "abd", (size_t)-1) >= 0) {
        fprintf(stderr, "strncmp SIZE_MAX failed\n");
        return 111;
    }
    typedef char *(*strnstr_fn)(const char *, const char *, size_t);
    strnstr_fn fl_strnstr = (strnstr_fn)dlsym(RTLD_DEFAULT, "strnstr");
    if (fl_strnstr == NULL || fl_strnstr(hay, "Xgh", (size_t)-1) != hay + 6) {
        fprintf(stderr, "strnstr SIZE_MAX failed\n");
        return 112;
    }
    wchar_t whay[16] = L"abcdZefg";
    if (wcsnlen(whay, (size_t)-1) != 8) {
        fprintf(stderr, "wcsnlen SIZE_MAX failed\n");
        return 113;
    }
    if (wmemchr(whay, L'Z', (size_t)-1) != whay + 4) {
        fprintf(stderr, "wmemchr SIZE_MAX failed\n");
        return 114;
    }
    const char *mode_env = getenv("FRANKENLIBC_MODE");
    if (mode_env != NULL && strcmp(mode_env, "hardened") == 0) {
        wchar_t *wdst = (wchar_t *)malloc(4 * sizeof(wchar_t));
        if (wdst == NULL) return 115;
        wchar_t *wend = wcpncpy(wdst, L"ab", 64);
        if (wend != wdst + 2 || wdst[0] != L'a' || wdst[1] != L'b' || wdst[2] != 0 || wdst[3] != 0) {
            fprintf(stderr, "hardened wcpncpy dst clamp failed\n");
            free(wdst);
            return 116;
        }
        free(wdst);
    }

    // 2. fclose(fp) followed by fflush(fp) on an owned stream must fail with EBADF.
    FILE *tmp = tmpfile();
    if (tmp == NULL) {
        fprintf(stderr, "tmpfile failed\n");
        return 12;
    }
    if (fputs("hello", tmp) < 0) return 13;
    if (fclose(tmp) != 0) return 14;
    errno = 0;
    int fl_rc = fflush(tmp);
    if (fl_rc != EOF || errno != EBADF) {
        fprintf(stderr, "closed fflush expected EOF/EBADF, got rc=%d errno=%d\n", fl_rc, errno);
        return 15;
    }

    // 3. -no-pie copy-relocated `environ = custom_env` synchronization + setenv/unsetenv/clearenv.
    static char entry_a[] = "WAVE7_A=alpha";
    static char entry_b[] = "WAVE7_B=beta";
    char *custom_env[3];
    custom_env[0] = entry_a;
    custom_env[1] = entry_b;
    custom_env[2] = NULL;
    environ = custom_env;

    const char *va = getenv("WAVE7_A");
    if (va == NULL || strcmp(va, "alpha") != 0) {
        fprintf(stderr, "getenv after environ=custom_env failed: %s\n", va ? va : "NULL");
        return 21;
    }
    if (setenv("WAVE7_C", "gamma", 1) != 0) return 22;
    if (environ == NULL || environ != _environ || environ != __environ) {
        fprintf(stderr, "environ aliases desynchronized after setenv: %p / %p / %p\n",
                (void *)environ, (void *)_environ, (void *)__environ);
        return 23;
    }
    const char *vc = getenv("WAVE7_C");
    if (vc == NULL || strcmp(vc, "gamma") != 0) return 24;
    if (unsetenv("WAVE7_B") != 0) return 25;
    if (getenv("WAVE7_B") != NULL) return 26;
    if (clearenv() != 0) return 27;
    if (environ != NULL || _environ != NULL || __environ != NULL || getenv("WAVE7_A") != NULL) {
        fprintf(stderr, "clearenv failed: environ=%p _environ=%p __environ=%p\n",
                (void *)environ, (void *)_environ, (void *)__environ);
        return 28;
    }
    if (setenv("PATH", "/usr/bin:/bin", 1) != 0) return 29;

    // 4. Main-thread per-thread locale must survive across pthread_create (incl. FRANKENLIBC_THREAD_NATIVE=1)
    //    AND pthread_key_create destructors must safely use ABI TLS cells!
    locale_t c_loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    if (c_loc == (locale_t)0) return 30;
    if (uselocale(c_loc) == (locale_t)0) return 31;

    if (pthread_key_create(&g_key_round1, key_dtor_round1) != 0) return 32;
    if (pthread_key_create(&g_key_round2, key_dtor_round2) != 0) return 33;

    pthread_t th;
    if (pthread_create(&th, NULL, tls_dtor_worker, NULL) != 0) return 34;
    void *ret = NULL;
    if (pthread_join(th, &ret) != 0 || ret != NULL) return 35;

    if (g_dtor_ok != 11) {
        fprintf(stderr, "pthread_key_create destructors failed: g_dtor_ok=%d\n", g_dtor_ok);
        return 36;
    }
    if (uselocale((locale_t)0) != c_loc) {
        fprintf(stderr, "main-thread uselocale lost across pthread_create!\n");
        return 37;
    }
    uselocale(LC_GLOBAL_LOCALE);
    freelocale(c_loc);
    pthread_key_delete(g_key_round1);
    pthread_key_delete(g_key_round2);
    return 0;
}
"#,
    )
    .expect("write wave7_probe.c");

    let bin = out_dir.join("wave7_probe_no_pie");
    let status = Command::new("cc")
        .args([
            "-O2",
            "-U_FORTIFY_SOURCE",
            "-D_FORTIFY_SOURCE=0",
            "-fno-builtin",
            "-fno-pie",
            "-no-pie",
            "-Wall",
            "-Wextra",
            "-Wno-use-after-free",
            "-Werror",
        ])
        .arg(&c_src)
        .arg("-ldl")
        .arg("-lpthread")
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("compile wave7_probe.c");
    assert!(status.success(), "cc wave7_probe.c failed");

    for mode in ["strict", "hardened"] {
        for native_threads in ["0", "1"] {
            let mut cmd = Command::new(&bin);
            cmd.env("LD_PRELOAD", &so_path)
                .env("FRANKENLIBC_MODE", mode);
            if native_threads == "1" {
                cmd.env("FRANKENLIBC_THREAD_NATIVE", "1");
            } else {
                cmd.env_remove("FRANKENLIBC_THREAD_NATIVE");
            }
            let out = cmd.output().expect("execute wave7_probe_no_pie");
            assert!(
                out.status.success(),
                "wave7_probe failed (mode={mode}, native={native_threads}, code={:?}):\nstdout={}\nstderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
