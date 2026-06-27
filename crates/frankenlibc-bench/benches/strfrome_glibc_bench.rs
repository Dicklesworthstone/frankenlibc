//! In-process A/B: frankenlibc CORE `render_pct_e` (the `%e` body formatter behind
//! `strfromd`) vs REAL in-process glibc `strfromd("%.*e", x)`. Links NO fl ABI
//! symbols, so the extern resolves to host glibc. Positive values only (sign is
//! handled by strfromd's caller; render_pct_e formats the magnitude body).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strfrome_glibc_bench`

use std::ffi::{c_char, c_int};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

unsafe extern "C" {
    fn strfromd(str: *mut c_char, n: usize, format: *const c_char, fp: f64) -> c_int;
}

const CASES: &[(&str, f64, usize)] = &[
    ("pi_p6", 3.141592653589793, 6),
    ("pi_p17", 3.141592653589793, 17),
    ("mid_p6", 1234567.89, 6),
    ("small_p15", 0.0001234, 15),
    ("dblmax_p17", 1.7976931348623157e308, 17),
];

fn gl_strfrome(value: f64, prec: usize) -> Vec<u8> {
    let fmt = std::ffi::CString::new(format!("%.{prec}e")).unwrap();
    let mut buf = [0i8; 64];
    unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), value) };
    buf.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect()
}

fn bench(c: &mut Criterion) {
    // Byte-identity check vs glibc before benching each case.
    for (name, value, prec) in CASES {
        let fl = frankenlibc_core::stdlib::ecvt::render_pct_e(*value, *prec);
        let gl = gl_strfrome(*value, *prec);
        assert_eq!(
            fl.as_bytes(),
            gl.as_slice(),
            "render_pct_e mismatch {name}: fl={fl:?} gl={:?}",
            String::from_utf8_lossy(&gl)
        );
    }

    for (name, value, prec) in CASES {
        let fmt = std::ffi::CString::new(format!("%.{prec}e")).unwrap();
        let mut g = c.benchmark_group(format!("strfrome_{name}"));
        g.bench_function("frankenlibc_core", |b| {
            b.iter(|| black_box(frankenlibc_core::stdlib::ecvt::render_pct_e(black_box(*value), *prec)))
        });
        g.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut buf = [0i8; 64];
                black_box(unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), black_box(*value)) });
            })
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
