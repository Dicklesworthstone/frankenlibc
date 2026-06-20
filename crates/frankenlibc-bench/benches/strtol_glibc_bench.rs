//! Head-to-head numeric-parse benchmark: FrankenLibC vs host glibc.
//!
//! Measures the DEPLOYED ABI strtol/strtoul/strtod/strtof path (`frankenlibc_abi::
//! stdlib_abi::*`) — this is a criterion bench, so the lib is built WITHOUT
//! `cfg(test)`, i.e. the membrane fast-paths are live and `known_remaining`
//! routes through the cheap deployed bookkeeping (unlike a `--test` integration
//! bench, which compiles the lib with `cfg(test)=true` and measures the slow
//! validate_ptr path — see NEGATIVE_EVIDENCE 2026-06-20 strtol artifact).
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM, "libc.so.6")` so fl's `no_mangle`
//! symbols do not interpose the host.

use std::ffi::{c_char, c_int};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};

type StrtolFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char, c_int) -> i64;
type StrtodFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> f64;

fn host(name: &[u8]) -> usize {
    static H: OnceLock<usize> = OnceLock::new();
    let handle = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        h as usize
    });
    let p = unsafe { libc::dlsym(handle as *mut _, name.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym failed");
    p as usize
}

fn report(label: &str, samples: &mut [f64]) {
    if samples.is_empty() {
        return;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = samples[samples.len() / 2];
    println!("STRTOL_BENCH impl={label} p50_ns_op={p50:.2}");
}

fn time_it<F: FnMut() -> i64>(mut f: F) -> f64 {
    let mut s: Vec<f64> = Vec::new();
    for _ in 0..200 {
        let iters = 2000u64;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(f());
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        s.push(dur.as_nanos() as f64 / iters as f64);
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s[s.len() / 2]
}

fn bench(c: &mut Criterion) {
    let gstrtol: StrtolFn = unsafe { std::mem::transmute(host(b"strtol\0")) };
    let gstrtod: StrtodFn = unsafe { std::mem::transmute(host(b"strtod\0")) };
    let mut group = c.benchmark_group("numeric_parse");
    group.sample_size(10);

    // strtol cases
    for (name, s, base) in [
        ("strtol_dec_short", b"42\0".as_slice(), 10i32),
        ("strtol_dec_long", b"1234567890\0", 10),
        ("strtol_hex", b"0xdeadbeef\0", 16),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { frankenlibc_abi::stdlib_abi::strtol(black_box(p), &mut e, base) }
        });
        let gl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { gstrtol(black_box(p), &mut e, base) }
        });
        println!("{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}", fl / gl);
    }

    // atoi / atol (no endptr; super-common)
    type AtoiFn = unsafe extern "C" fn(*const c_char) -> c_int;
    let gatoi: AtoiFn = unsafe { std::mem::transmute(host(b"atoi\0")) };
    for (name, s) in [("atoi_short", b"42\0".as_slice()), ("atoi_long", b"1234567890\0")] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| unsafe { frankenlibc_abi::stdlib_abi::atoi(black_box(p)) as i64 });
        let gl = time_it(|| unsafe { gatoi(black_box(p)) as i64 });
        println!("{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}", fl / gl);
    }

    // strtod cases
    for (name, s) in [
        ("strtod_int", b"12345\0".as_slice()),
        ("strtod_simple", b"3.14159\0"),
        ("strtod_sci", b"1.234567e10\0"),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { frankenlibc_abi::stdlib_abi::strtod(black_box(p), &mut e) as i64 }
        });
        let gl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { gstrtod(black_box(p), &mut e) as i64 }
        });
        println!("{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}", fl / gl);
    }

    let _ = report;
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
