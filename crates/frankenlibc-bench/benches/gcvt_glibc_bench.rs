//! RELIABLE in-process A/B: frankenlibc CORE `gcvt` (double -> "%g" string) vs
//! REAL in-process glibc `gcvt`. Links NO fl ABI symbols, so the `extern "C" fn
//! gcvt` resolves to host glibc and `frankenlibc_core::stdlib::ecvt::gcvt` is
//! callable directly — a trustworthy head-to-head.
//!
//! glibc's gcvt/printf-%g use the classic dragon (multiprecision) digit
//! generation; fl's renders via Rust std `format!` (Grisu/Ryū-class). This is
//! the formatting complement to `strtod_glibc_bench` (the parse direction).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench gcvt_glibc_bench`

use std::ffi::c_char;
use std::ffi::c_int;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

unsafe extern "C" {
    fn gcvt(value: f64, ndigit: c_int, buf: *mut c_char) -> *mut c_char;
}

const CASES: &[(&str, f64, i32)] = &[
    ("pi_p17", 3.141592653589793, 17),
    ("pi_p6", 3.141592653589793, 6),
    ("mid_p17", 1234567.89, 17),
    ("small_p17", 0.0001234, 17),
    ("dblmax_p17", 1.7976931348623157e308, 17),
    ("round_p6", 100000.0, 6),
    ("simple_p6", 2.5, 6),
];

fn fl_gcvt(value: f64, ndigit: i32, buf: &mut [u8]) -> usize {
    frankenlibc_core::stdlib::ecvt::gcvt(value, ndigit, buf)
}

fn bench(c: &mut Criterion) {
    // Verify byte-exact parity vs host glibc before benching each case.
    for (name, value, ndigit) in CASES {
        let mut fl_buf = [0u8; 64];
        let n = fl_gcvt(*value, *ndigit, &mut fl_buf);
        let fl_str = &fl_buf[..n];

        let mut gl_buf = [0i8; 64];
        unsafe { gcvt(*value, *ndigit as c_int, gl_buf.as_mut_ptr()) };
        let gl_bytes: Vec<u8> = gl_buf
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();

        assert_eq!(
            fl_str,
            gl_bytes.as_slice(),
            "gcvt mismatch on {name}: fl={:?} gl={:?}",
            String::from_utf8_lossy(fl_str),
            String::from_utf8_lossy(&gl_bytes)
        );
    }

    for (name, value, ndigit) in CASES {
        let mut g = c.benchmark_group(format!("gcvt_{name}"));
        g.bench_function("frankenlibc_core", |b| {
            let mut buf = [0u8; 64];
            b.iter(|| {
                black_box(fl_gcvt(black_box(*value), black_box(*ndigit), &mut buf));
            })
        });
        g.bench_function("host_glibc_inprocess", |b| {
            let mut buf = [0i8; 64];
            b.iter(|| {
                black_box(unsafe {
                    gcvt(black_box(*value), black_box(*ndigit as c_int), buf.as_mut_ptr())
                });
            })
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
