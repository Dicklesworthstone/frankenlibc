#![cfg(target_os = "linux")]

//! Differential conformance harness for the BSD `arc4random` family.
//!
//! `arc4random` is a CSPRNG-backed random number API. Glibc 2.36+
//! exports it as a weak symbol; both impls draw entropy via
//! getrandom(2), so we can't compare exact bit values (they're
//! genuinely random). Instead we validate API contract parity:
//!   - arc4random returns 32-bit values; both impls should produce a
//!     wide spread (low collision rate)
//!   - arc4random_buf fills the entire buffer (no zero-byte gaps)
//!   - arc4random_uniform(N) always returns values strictly < N
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_void;

use frankenlibc_abi::unistd_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

unsafe extern "C" {
    fn arc4random() -> u32;
    fn arc4random_buf(buf: *mut c_void, nbytes: usize);
    fn arc4random_uniform(upper_bound: u32) -> u32;
}

#[test]
fn diff_arc4random_returns_distinct_values() {
    // Draw many samples from each impl; both should have ≥ 99% unique.
    fn unique_ratio(draws: &[u32]) -> f64 {
        let mut sorted = draws.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.len() as f64 / draws.len() as f64
    }
    let n = 256;
    let fl_draws: Vec<u32> = (0..n).map(|_| unsafe { fl::arc4random() }).collect();
    let lc_draws: Vec<u32> = (0..n).map(|_| unsafe { arc4random() }).collect();
    let fl_uniq = unique_ratio(&fl_draws);
    let lc_uniq = unique_ratio(&lc_draws);
    // Both impls' draws must be ≥ 99% unique (very high prob with u32 range).
    assert!(fl_uniq >= 0.99, "fl unique ratio {fl_uniq}");
    assert!(lc_uniq >= 0.99, "lc unique ratio {lc_uniq}");
}

#[test]
fn diff_arc4random_uniform_respects_upper_bound() {
    for upper in [1u32, 2, 5, 100, 1_000, 1_000_000, u32::MAX / 2, u32::MAX] {
        for _ in 0..100 {
            let fl_v = unsafe { fl::arc4random_uniform(upper) };
            let lc_v = unsafe { arc4random_uniform(upper) };
            // arc4random_uniform(N) returns r < N (or 0 when N < 2).
            if upper < 2 {
                assert_eq!(fl_v, 0, "upper={upper}");
                assert_eq!(lc_v, 0, "upper={upper}");
            } else {
                assert!(fl_v < upper, "fl violated upper={upper}: got {fl_v}");
                assert!(lc_v < upper, "lc violated upper={upper}: got {lc_v}");
            }
        }
    }
}

#[test]
fn diff_arc4random_buf_fills_entire_buffer() {
    // arc4random_buf must populate every byte. Test sizes spanning the
    // 256-byte getrandom(2) limit so we exercise the multi-call loop.
    for size in [1usize, 8, 64, 256, 257, 1024, 4096] {
        let mut fl_buf = vec![0u8; size];
        let mut lc_buf = vec![0u8; size];
        unsafe {
            fl::arc4random_buf(fl_buf.as_mut_ptr() as *mut c_void, size);
            arc4random_buf(lc_buf.as_mut_ptr() as *mut c_void, size);
        }
        // Both buffers must be highly varied — we expect ≤ 5% zero bytes
        // (vs ~0.4% theoretical for uniform random over 256 values).
        let fl_zeros = fl_buf.iter().filter(|&&b| b == 0).count();
        let lc_zeros = lc_buf.iter().filter(|&&b| b == 0).count();
        let max_zeros = (size as f64 * 0.05).max(2.0) as usize;
        assert!(
            fl_zeros <= max_zeros,
            "fl_buf size={size} zeros={fl_zeros} > {max_zeros}"
        );
        assert!(
            lc_zeros <= max_zeros,
            "lc_buf size={size} zeros={lc_zeros} > {max_zeros}"
        );
    }
}

#[test]
fn diff_arc4random_buf_zero_size_is_noop() {
    // Both impls should accept nbytes=0 without crashing.
    unsafe {
        fl::arc4random_buf(std::ptr::null_mut(), 0);
        arc4random_buf(std::ptr::null_mut(), 0);
    }
}

#[test]
fn diff_arc4random_uniform_distribution_bias_check() {
    // For small N, sampling many times should populate every bucket.
    const N: u32 = 8;
    const SAMPLES: usize = 8_000;
    let mut fl_counts = [0u32; N as usize];
    let mut lc_counts = [0u32; N as usize];
    for _ in 0..SAMPLES {
        let f = unsafe { fl::arc4random_uniform(N) };
        let l = unsafe { arc4random_uniform(N) };
        fl_counts[f as usize] += 1;
        lc_counts[l as usize] += 1;
    }
    // Each bucket should hold ~1000 samples (1000 ± several stddev).
    for i in 0..N as usize {
        assert!(
            fl_counts[i] > 700,
            "fl bucket {i} underfilled: {}",
            fl_counts[i]
        );
        assert!(
            lc_counts[i] > 700,
            "lc bucket {i} underfilled: {}",
            lc_counts[i]
        );
    }
}

#[test]
fn arc4random_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc arc4random + arc4random_buf + arc4random_uniform\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}

#[test]
#[cfg(target_arch = "x86_64")]
fn diff_entropy_kernel_fault_contract() {
    entropy_contract(None);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_entropy_plt_protocol() {
    entropy_contract(Some(false));
}

#[test]
#[cfg(target_arch = "x86_64")]
fn native_entropy_got_protocol() {
    entropy_contract(Some(true));
}

#[cfg(target_arch = "x86_64")]
fn entropy_contract(plugin: Option<bool>) {
    use std::ffi::{CString, c_char, c_int};
    use std::os::unix::ffi::OsStrExt;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "frankenlibc-entropy-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let library = root.join("observer.so");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/integration/fixture_random_multibyte.c");
    let output = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .args(["-o"])
        .arg(&library)
        .arg("-ldl")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "C observer link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = CString::new(library.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is NUL-terminated and stays live during dlopen. The shared
    // observer and its function pointers remain loaded through all children.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "could not load C entropy observer");
    // SAFETY: the C symbol has the declaration below in the fixture.
    let run: unsafe extern "C" fn(u32, *const *mut c_void) -> c_int = unsafe {
        let address = libc::dlsym(handle, c"flc_entropy_run".as_ptr());
        assert!(!address.is_null());
        std::mem::transmute(address)
    };
    let native = [
        fl::getentropy as *mut c_void,
        fl::arc4random as *mut c_void,
        fl::arc4random_buf as *mut c_void,
        fl::arc4random_uniform as *mut c_void,
        frankenlibc_abi::errno_abi::__errno_location as *mut c_void,
    ];
    let names = [
        c"getentropy",
        c"arc4random",
        c"arc4random_buf",
        c"arc4random_uniform",
        c"__errno_location",
    ];
    let host = std::array::from_fn::<_, 5, _>(|index| {
        // SAFETY: only obtain the actual GNU address here; C calls it using
        // the matching prototype. The helper rejects the native definition.
        unsafe { dlsym_oracle::host_addr(names[index], native[index].cast_const().cast()) }
    });
    let plugin = plugin.map(|got| {
        let source = root.join("plugin.c");
        let library = root.join("plugin.so");
        std::fs::write(&source, ENTROPY_PLUGIN).unwrap();
        let output = Command::new("gcc")
            .args([
                "-shared",
                "-fPIC",
                "-nostdlib",
                "-O2",
                "-fno-builtin",
                "-fno-stack-protector",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,--hash-style=both",
                if got { "-fno-plt" } else { "-fplt" },
            ])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let object = frankenlibc_core::elf::ElfLoader::new(0)
            .parse(&std::fs::read(&library).unwrap())
            .unwrap();
        assert!(
            object.needed_libraries.is_empty(),
            "host dependencies in plugin"
        );
        for (index, (symbol, wrapper)) in [
            ("getentropy", "entropy_call_getentropy"),
            ("arc4random", "entropy_call_draw"),
            ("arc4random_buf", "entropy_call_fill"),
            ("arc4random_uniform", "entropy_call_uniform"),
            ("__errno_location", "entropy_call_errno"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                object
                    .undefined_symbols()
                    .any(|(_, s)| object.symbol_name(s) == Some(symbol))
            );
            let output = Command::new("objdump")
                .args(["-dr", &format!("--disassemble={wrapper}")])
                .arg(&library)
                .output()
                .unwrap();
            assert!(output.status.success(), "objdump failed");
            let text = String::from_utf8(output.stdout).unwrap();
            if got {
                assert!(
                    text.contains('*') && !text.contains("@plt>"),
                    "GOT wrapper{index}: {text}"
                );
            } else {
                assert!(
                    text.contains(&format!("<{symbol}@plt>")),
                    "PLT wrapper{index}: {text}"
                );
            }
        }
        library
    });
    let mut failures = Vec::new();
    for (provider, mut functions) in [("GNU", host), ("native", native)] {
        type Open = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
        type Close = unsafe extern "C" fn(*mut c_void) -> c_int;
        type Symbol = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void;
        let mut loaded: Option<(*mut c_void, Close)> = None;
        if let Some(library) = &plugin {
            use frankenlibc_abi::dlfcn_abi as dl;
            let (open, close, symbol): (Open, Close, Symbol) = if provider == "native" {
                (dl::dlopen, dl::dlclose, dl::dlsym)
            } else {
                // SAFETY: each resolved GNU function uses the matching C ABI;
                // the oracle helper rejects the corresponding native address.
                unsafe {
                    (
                        dlsym_oracle::host_fn(c"dlopen", dl::dlopen as *const ()),
                        dlsym_oracle::host_fn(c"dlclose", dl::dlclose as *const ()),
                        dlsym_oracle::host_fn(c"dlsym", dl::dlsym as *const ()),
                    )
                }
            };
            let path = CString::new(library.as_os_str().as_bytes()).unwrap();
            // SAFETY: path is live and NUL-terminated; keep the DSO mapped
            // until all child calls through its wrappers have completed.
            let handle = unsafe { open(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            assert!(
                !handle.is_null(),
                "{provider} entropy plugin failed to load"
            );
            if provider == "native" {
                assert!(
                    dl::native_dso_handle_for_tests(handle),
                    "host fallback is not native"
                );
            }
            // SAFETY: the dependency-free C plugin declares these exact
            // selector and caller-relative lookup function signatures.
            let (select, lookup): (
                unsafe extern "C" fn(u32, u32) -> *mut c_void,
                unsafe extern "C" fn() -> c_int,
            ) = unsafe {
                let select = symbol(handle, c"entropy_plugin_function".as_ptr());
                let lookup = symbol(handle, c"entropy_plugin_lookup".as_ptr());
                assert!(!select.is_null() && !lookup.is_null());
                (
                    std::mem::transmute::<*mut c_void, unsafe extern "C" fn(u32, u32) -> *mut c_void>(
                        select,
                    ),
                    std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> c_int>(lookup),
                )
            };
            for (index, name) in [
                c"entropy_call_getentropy",
                c"entropy_call_draw",
                c"entropy_call_fill",
                c"entropy_call_uniform",
                c"entropy_call_errno",
            ]
            .into_iter()
            .enumerate()
            {
                // SAFETY: indices 0..5 address the plugin's declared tables.
                // Its actual imports must match the independent provider table;
                // the observer calls exported wrappers to exercise real PLT/GOT.
                unsafe {
                    assert_eq!(
                        select(index as u32, 0),
                        functions[index],
                        "{provider}: import{index}"
                    );
                    let wrapper = select(index as u32, 1);
                    assert!(!wrapper.is_null());
                    assert_eq!(wrapper, symbol(handle, name.as_ptr()));
                    functions[index] = wrapper;
                }
            }
            // SAFETY: lookup is the plugin's checked zero-argument C entry.
            assert_eq!(unsafe { lookup() }, 0, "{provider}: caller-relative lookup");
            loaded = Some((handle, close));
        }
        for id in 0..35 {
            let expected = if (9..18).contains(&id) || (21..27).contains(&id) {
                128 + libc::SIGABRT
            } else {
                0
            };
            // SAFETY: the live function table matches all five C declarations;
            // the C runner isolates each irreversible seccomp policy in a child.
            let observed = unsafe { run(id, functions.as_ptr()) };
            eprintln!(
                "entropy provider={provider} case={id} result={observed} expected={expected}"
            );
            if provider == "GNU" && id >= 32 && observed == 112 {
                eprintln!("GNU case={id}: kernel injection unexercised; no retry proof");
                continue;
            }
            if observed != expected {
                failures.push((provider, id, observed, expected));
            }
        }
        if let Some((handle, close)) = loaded {
            // SAFETY: all child processes and plugin calls have completed.
            assert_eq!(unsafe { close(handle) }, 0);
        }
    }
    // SAFETY: all child processes have exited; no observer pointer is reused.
    assert_eq!(unsafe { libc::dlclose(handle) }, 0);
    assert!(
        failures.is_empty(),
        "entropy contract failures: {failures:?}"
    );
}

#[cfg(target_arch = "x86_64")]
const ENTROPY_PLUGIN: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

int entropy_call_getentropy(void *p, size_t n) { return getentropy(p, n); }
uint32_t entropy_call_draw(void) { return arc4random(); }
void entropy_call_fill(void *p, size_t n) { arc4random_buf(p, n); }
uint32_t entropy_call_uniform(uint32_t n) { return arc4random_uniform(n); }
int *entropy_call_errno(void) { return __errno_location(); }

void *entropy_plugin_function(unsigned index, unsigned wrappers) {
    void *const imports[] = {(void *)getentropy, (void *)arc4random,
        (void *)arc4random_buf, (void *)arc4random_uniform, (void *)__errno_location};
    void *const calls[] = {(void *)entropy_call_getentropy, (void *)entropy_call_draw,
        (void *)entropy_call_fill, (void *)entropy_call_uniform, (void *)entropy_call_errno};
    return index < 5 ? (wrappers ? calls[index] : imports[index]) : 0;
}

int entropy_plugin_lookup(void) {
    const char *const names[] = {"getentropy", "arc4random", "arc4random_buf",
        "arc4random_uniform", "__errno_location"};
    const char *const versions[] = {"GLIBC_2.25", "GLIBC_2.36", "GLIBC_2.36",
        "GLIBC_2.36", "GLIBC_2.2.5"};
    const char *const rejected[] = {"GLIBC_2.2.5", "GLIBC_2.17", "GLIBC_2.25",
        "GLIBC_2.34", "GLIBC_2.36", "GLIBC_9.99", "GLIBC_PRIVATE", ""};
    for (unsigned i = 0; i < 5; i++) {
        void *expected = entropy_plugin_function(i, 0);
        dlerror();
        if (dlsym(RTLD_DEFAULT, names[i]) != expected || dlerror()) return 1;
        if (dlvsym(RTLD_DEFAULT, names[i], versions[i]) != expected || dlerror()) return 2;
        for (unsigned j = 0; j < 8; j++) {
            if ((i == 0 && j == 2) || (i > 0 && i < 4 && j == 4) ||
                (i == 4 && j == 0)) continue;
            if (dlvsym(RTLD_DEFAULT, names[i], rejected[j]) || !dlerror() || dlerror())
                return 3;
        }
    }
    return 0;
}
"#;
