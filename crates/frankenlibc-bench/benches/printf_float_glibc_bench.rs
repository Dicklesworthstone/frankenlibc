//! In-process A/B: deployed printf float formatters `format_g`/`format_e` (now
//! delegating to the heap-lean `render_pct_g`/`render_pct_e`) vs real in-process
//! glibc `strfromd("%.*g"/"%.*e")`. Confirms the printf %g/%e CORE formatting,
//! isolated from the variadic dispatch, now matches the optimized strfrom path.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench printf_float_glibc_bench`

use std::ffi::{c_char, c_int};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

unsafe extern "C" {
    fn strfromd(str: *mut c_char, n: usize, format: *const c_char, fp: f64) -> c_int;
}

const CASES: &[(&str, f64, usize)] = &[
    ("g_pi_p6", 3.141592653589793, 6),
    ("g_mid_p17", 1234567.89, 17),
    ("e_pi_p6", 3.141592653589793, 6),
    ("e_mid_p6", 1234567.89, 6),
];

fn gl(value: f64, prec: usize, conv: char) -> Vec<u8> {
    let fmt = std::ffi::CString::new(format!("%.{prec}{conv}")).unwrap();
    let mut buf = [0i8; 64];
    unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), value) };
    buf.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect()
}

fn bench(c: &mut Criterion) {
    // Parity vs glibc for each (format_g/e produce the unsigned body; positive inputs).
    for (name, value, prec) in CASES {
        let is_g = name.starts_with('g');
        let fl = if is_g {
            frankenlibc_core::stdio::printf::__bench_format_g(*value, *prec)
        } else {
            frankenlibc_core::stdio::printf::__bench_format_e(*value, *prec)
        };
        let g = gl(*value, *prec, if is_g { 'g' } else { 'e' });
        assert_eq!(fl.as_bytes(), g.as_slice(), "printf {name} mismatch vs glibc");
    }

    for (name, value, prec) in CASES {
        let is_g = name.starts_with('g');
        let conv = if is_g { 'g' } else { 'e' };
        let fmt = std::ffi::CString::new(format!("%.{prec}{conv}")).unwrap();
        let mut grp = c.benchmark_group(format!("printffloat_{name}"));
        grp.bench_function("frankenlibc_core", |b| {
            b.iter(|| {
                if is_g {
                    black_box(frankenlibc_core::stdio::printf::__bench_format_g(black_box(*value), *prec))
                } else {
                    black_box(frankenlibc_core::stdio::printf::__bench_format_e(black_box(*value), *prec))
                }
            })
        });
        grp.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut buf = [0i8; 64];
                black_box(unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), black_box(*value)) });
            })
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
