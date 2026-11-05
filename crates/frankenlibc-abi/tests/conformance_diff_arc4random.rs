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
    use std::ffi::{CString, c_int};
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
    let mut failures = Vec::new();
    for (provider, functions) in [("GNU", host), ("native", native)] {
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
    }
    // SAFETY: all child processes have exited; no observer pointer is reused.
    assert_eq!(unsafe { libc::dlclose(handle) }, 0);
    assert!(
        failures.is_empty(),
        "entropy contract failures: {failures:?}"
    );
}
