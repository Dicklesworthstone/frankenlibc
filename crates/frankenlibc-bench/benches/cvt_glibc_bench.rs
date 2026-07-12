//! In-process A/B: frankenlibc CORE `ecvt`/`fcvt` (double -> digit string) vs
//! REAL in-process glibc `ecvt`/`fcvt`. Links NO fl ABI symbols, so the extern
//! resolves to host glibc and `frankenlibc_core::stdlib::ecvt::{ecvt,fcvt}` is
//! callable directly — a trustworthy head-to-head.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench cvt_glibc_bench`

use std::ffi::c_char;
use std::ffi::c_int;
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

unsafe extern "C" {
    fn ecvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char;
    fn fcvt(value: f64, ndigit: c_int, decpt: *mut c_int, sign: *mut c_int) -> *mut c_char;
}

// NB: DBL_MAX/extreme magnitudes are intentionally excluded — fl ecvt is
// deliberately MORE correct than glibc there (documented non-mirror,
// bd-2g7oyh.101), so a byte-equality parity assert would (correctly) differ.
const CASES: &[(&str, f64, i32)] = &[
    ("pi_17", 3.141592653589793, 17),
    ("pi_6", 3.141592653589793, 6),
    ("mid_17", 1234567.89, 17),
    ("small_15", 0.0001234, 15),
    ("hundredk_9", 123456.789, 9),
];

fn gl_digits(value: f64, ndigit: i32, fcvt_mode: bool) -> (Vec<u8>, i32, bool) {
    let mut decpt: c_int = 0;
    let mut sign: c_int = 0;
    let p = unsafe {
        if fcvt_mode {
            fcvt(value, ndigit as c_int, &mut decpt, &mut sign)
        } else {
            ecvt(value, ndigit as c_int, &mut decpt, &mut sign)
        }
    };
    let mut digits = Vec::new();
    let mut i = 0;
    loop {
        let b = unsafe { *p.add(i) } as u8;
        if b == 0 {
            break;
        }
        digits.push(b);
        i += 1;
    }
    (digits, decpt, sign != 0)
}

fn bench(c: &mut Criterion) {
    // Parity check vs host glibc for ecvt (fcvt's digit-string semantics differ
    // subtly across libc versions for some edges, so we only assert ecvt here and
    // bench both).
    for (name, value, ndigit) in CASES {
        let (fl_d, fl_dp, fl_s) = frankenlibc_core::stdlib::ecvt::ecvt(*value, *ndigit);
        let (gl_d, gl_dp, gl_s) = gl_digits(*value, *ndigit, false);
        assert_eq!(fl_d, gl_d, "ecvt digits mismatch {name}");
        assert_eq!(fl_dp, gl_dp, "ecvt decpt mismatch {name}");
        assert_eq!(fl_s, gl_s, "ecvt sign mismatch {name}");
    }

    for (name, value, ndigit) in CASES {
        let mut ge = c.benchmark_group(format!("ecvt_{name}"));
        ge.bench_function("frankenlibc_core", |b| {
            b.iter(|| {
                black_box(frankenlibc_core::stdlib::ecvt::ecvt(
                    black_box(*value),
                    *ndigit,
                ))
            })
        });
        ge.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut dp: c_int = 0;
                let mut sg: c_int = 0;
                black_box(unsafe { ecvt(black_box(*value), *ndigit as c_int, &mut dp, &mut sg) });
            })
        });
        ge.finish();

        let mut gf = c.benchmark_group(format!("fcvt_{name}"));
        gf.bench_function("frankenlibc_core", |b| {
            b.iter(|| {
                black_box(frankenlibc_core::stdlib::ecvt::fcvt(
                    black_box(*value),
                    *ndigit,
                ))
            })
        });
        gf.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut dp: c_int = 0;
                let mut sg: c_int = 0;
                black_box(unsafe { fcvt(black_box(*value), *ndigit as c_int, &mut dp, &mut sg) });
            })
        });
        gf.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
