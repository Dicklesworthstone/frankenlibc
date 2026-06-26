//! RELIABLE in-process A/B: frankenlibc CORE `strtod` vs REAL in-process glibc
//! `strtod`. This bench links NO fl ABI symbols, so the `extern "C" fn strtod`
//! resolves to the host glibc (ifunc-resolved in-process) and
//! `frankenlibc_core::stdlib::conversion::strtod_impl` is callable directly —
//! a trustworthy head-to-head (unlike abi-bench, which would shadow glibc).
//!
//! glibc's strtod uses a slow multiprecision (bignum) algorithm; fl's decimal
//! path delegates to Rust std `parse::<f64>()` (Eisel–Lemire / fast_float).
//! This measures whether that translates to a real win across input shapes.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strtod_glibc_bench`

use std::ffi::c_char;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

unsafe extern "C" {
    fn strtod(nptr: *const c_char, endptr: *mut *mut c_char) -> f64;
}

/// Inputs as NUL-terminated byte strings (fl `strtod_impl` runs `strlen`
/// internally; glibc needs a C string). Chosen to span common real shapes.
const CASES: &[(&str, &[u8])] = &[
    ("pi_15digit", b"3.14159265358979\0"),
    ("short_2digit", b"3.5\0"),
    ("integer_7digit", b"1000000\0"),
    ("many_digit_exp", b"123456789.123456789e-10\0"),
    ("max_double", b"1.7976931348623157e308\0"),
    ("long_frac_19", b"0.1234567890123456789\0"),
];

fn bench(c: &mut Criterion) {
    // Verify bit-exact parity vs host glibc for every case before benching.
    for (name, s) in CASES {
        let (fl, _, _) = frankenlibc_core::stdlib::conversion::strtod_impl(s);
        let gl = unsafe { strtod(s.as_ptr().cast::<c_char>(), std::ptr::null_mut()) };
        assert_eq!(
            fl.to_bits(),
            gl.to_bits(),
            "strtod bit mismatch on {name}: fl={fl} gl={gl}"
        );
    }

    for (name, s) in CASES {
        let mut g = c.benchmark_group(format!("strtod_{name}"));
        g.bench_function("frankenlibc_core", |b| {
            b.iter(|| black_box(frankenlibc_core::stdlib::conversion::strtod_impl(black_box(s))))
        });
        g.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                black_box(unsafe {
                    strtod(black_box(s.as_ptr().cast::<c_char>()), std::ptr::null_mut())
                })
            })
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
