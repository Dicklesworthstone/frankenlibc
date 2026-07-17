//! In-process A/B: deployed printf float formatters vs real in-process glibc
//! `strfromd("%.*f"/"%.*g"/"%.*e")`. The `%f` and `%g` rows also keep legacy
//! formatter arms as ORIG comparators for narrow fixed-digit fast paths.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench printf_float_glibc_bench`

use std::ffi::{c_char, c_int};
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

// INTEGRITY GUARD: this bench is valid ONLY while it references core-only functions
// (frankenlibc_core::stdio::printf::*). Do NOT add any arm that references a
// `frankenlibc_abi::*` function: doing so links fl's no_mangle allocator into the binary,
// which interposes malloc process-wide and inflates EVERY arm (core included) ~20-30x, AND
// flips this `strfromd` symbol from real host glibc to fl's own strfromd (both measured
// 2026-07-16). The comparison here is fl core formatter vs REAL glibc strfromd; keep it so.
unsafe extern "C" {
    fn strfromd(str: *mut c_char, n: usize, format: *const c_char, fp: f64) -> c_int;
}

const CASES: &[(&str, f64, usize)] = &[
    ("f_mid_p6", 12345.678901, 6),
    ("g_profile_p6", 12345.678901, 6),
    ("g_pi_p6", 3.141592653589793, 6),
    ("g_mid_p17", 1234567.89, 17),
    ("e_pi_p6", 3.141592653589793, 6),
    ("e_mid_p6", 1234567.89, 6),
];

fn gl(value: f64, prec: usize, conv: char) -> Vec<u8> {
    let fmt = std::ffi::CString::new(format!("%.{prec}{conv}")).unwrap();
    let mut buf = [0i8; 64];
    unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), value) };
    buf.iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as u8)
        .collect()
}

fn bench(c: &mut Criterion) {
    // Parity vs glibc for each (format_g/e produce the unsigned body; positive inputs).
    for (name, value, prec) in CASES {
        let conv = name.as_bytes()[0] as char;
        let fl = match conv {
            'f' => frankenlibc_core::stdio::printf::__bench_format_f(*value, *prec),
            'g' => frankenlibc_core::stdio::printf::__bench_format_g(*value, *prec),
            'e' => frankenlibc_core::stdio::printf::__bench_format_e(*value, *prec),
            _ => unreachable!(),
        };
        let g = gl(*value, *prec, conv);
        assert_eq!(
            fl.as_bytes(),
            g.as_slice(),
            "printf {name} mismatch vs glibc"
        );
    }

    for (name, value, prec) in CASES {
        let conv = name.as_bytes()[0] as char;
        let fmt = std::ffi::CString::new(format!("%.{prec}{conv}")).unwrap();
        let mut grp = c.benchmark_group(format!("printffloat_{name}"));
        grp.bench_function("frankenlibc_core", |b| {
            b.iter(|| {
                black_box(match conv {
                    'f' => {
                        frankenlibc_core::stdio::printf::__bench_format_f(black_box(*value), *prec)
                    }
                    'g' => {
                        frankenlibc_core::stdio::printf::__bench_format_g(black_box(*value), *prec)
                    }
                    'e' => {
                        frankenlibc_core::stdio::printf::__bench_format_e(black_box(*value), *prec)
                    }
                    _ => unreachable!(),
                })
            })
        });
        if conv == 'f' {
            grp.bench_function("frankenlibc_legacy_orig", |b| {
                b.iter(|| {
                    black_box(frankenlibc_core::stdio::printf::__bench_format_f_legacy(
                        black_box(*value),
                        *prec,
                    ))
                })
            });
        } else if conv == 'g' {
            grp.bench_function("frankenlibc_legacy_orig", |b| {
                b.iter(|| {
                    black_box(frankenlibc_core::stdio::printf::__bench_format_g_legacy(
                        black_box(*value),
                        *prec,
                    ))
                })
            });
        }
        grp.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut buf = [0i8; 64];
                black_box(unsafe {
                    strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), black_box(*value))
                });
            })
        });
        grp.finish();
    }
}

/// DEPLOYED `%e` path A/B: `render_pct_e_into` fed by the zero-alloc fixed-scaled
/// fast path (what real `printf("%e", ..)` runs) vs the legacy `render_pct_e_into`
/// alone vs in-process glibc. This is the path last change did NOT cover (only the
/// String `format_e` hook), so it measures the actual deployed win.
fn bench_deployed_e(c: &mut Criterion) {
    use frankenlibc_core::stdio::printf::__bench_render_pct_e_into;
    // `render_pct_e_into` is the real deployed `printf("%e", ..)` renderer; the
    // fixed-scaled fast path now lives inside it (after its dyadic path). Compare
    // vs glibc; the pre-change baseline is captured in the commit ledger from the
    // same pinned setup (legacy render_pct_e_into, glibc control stable).
    const E_CASES: &[(&str, f64, usize)] = &[
        ("dep_e_pi_p6", 3.141592653589793, 6),
        ("dep_e_simple_p6", 2.5, 6),
        ("dep_e_frac_p8", 0.0123456789, 8),
    ];
    for (name, value, prec) in E_CASES {
        let neu = __bench_render_pct_e_into(*value, *prec);
        let g = gl(*value, *prec, 'e');
        assert_eq!(neu.as_slice(), g.as_slice(), "{name}: != glibc");

        let fmt = std::ffi::CString::new(format!("%.{prec}e")).unwrap();
        let mut grp = c.benchmark_group(name.to_string());
        grp.bench_function("frankenlibc_core", |b| {
            b.iter(|| black_box(__bench_render_pct_e_into(black_box(*value), *prec)))
        });
        grp.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut buf = [0i8; 64];
                black_box(unsafe {
                    strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), black_box(*value))
                });
            })
        });
        grp.finish();
    }
}

/// DEPLOYED `%g` path A/B: `render_pct_g_into` (what real `printf("%g", ..)` runs)
/// vs in-process glibc. The fixed-scaled fast path now lives inside `render_gcvt_into`
/// after its exact-small probe; the pre-change baseline (~124ns for the pi/mid case)
/// is captured in the commit ledger from the same pinned setup.
fn bench_deployed_g(c: &mut Criterion) {
    use frankenlibc_core::stdlib::ecvt::render_pct_g_into;
    const G_CASES: &[(&str, f64, usize)] = &[
        ("dep_g_mid_p6", 12345.678901, 6),
        ("dep_g_pi_p6", 3.141592653589793, 6),
        ("dep_g_simple_p6", 2.5, 6),
    ];
    for (name, value, prec) in G_CASES {
        let mut neu = Vec::new();
        render_pct_g_into(*value, *prec, &mut neu);
        let g = gl(*value, *prec, 'g');
        assert_eq!(neu.as_slice(), g.as_slice(), "{name}: != glibc");

        let fmt = std::ffi::CString::new(format!("%.{prec}g")).unwrap();
        let mut grp = c.benchmark_group(name.to_string());
        grp.bench_function("frankenlibc_core", |b| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(32);
                render_pct_g_into(black_box(*value), *prec, &mut buf);
                black_box(buf)
            })
        });
        grp.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut buf = [0i8; 64];
                black_box(unsafe {
                    strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), black_box(*value))
                });
            })
        });
        grp.finish();
    }
}

/// Diagnostic: is `%a` (hex float, no precision) a loss vs glibc? fl format_a allocs a
/// String and has no deployed width-0 fast branch (only %e/%g do).
fn bench_diag_a(c: &mut Criterion) {
    use frankenlibc_core::stdio::printf::{
        FormatSegment, __bench_format_a, format_float, parse_format_string,
    };
    let a_spec = parse_format_string(b"%a")
        .as_slice()
        .iter()
        .find_map(|s| match s {
            FormatSegment::Spec(sp) => Some(*sp),
            _ => None,
        })
        .unwrap();
    for (name, value) in [("dbl", 12345.678901_f64), ("pi", std::f64::consts::PI)] {
        let fl = __bench_format_a(value);
        let g = {
            let fmt = std::ffi::CString::new("%a").unwrap();
            let mut buf = [0i8; 64];
            unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), value) };
            buf.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect::<Vec<u8>>()
        };
        assert_eq!(fl.as_bytes(), g.as_slice(), "%a {name} mismatch vs glibc");
        // deployed path parity check
        let mut dbuf = Vec::new();
        format_float(value, &a_spec, &mut dbuf);
        assert_eq!(dbuf.as_slice(), g.as_slice(), "%a {name} deployed mismatch");
        let fmt = std::ffi::CString::new("%a").unwrap();
        let mut grp = c.benchmark_group(format!("diag_a_{name}"));
        grp.bench_function("frankenlibc_core", |b| {
            b.iter(|| black_box(__bench_format_a(black_box(value))))
        });
        grp.bench_function("deployed_format_float", |b| {
            b.iter(|| {
                let mut buf = Vec::with_capacity(32);
                format_float(black_box(value), black_box(&a_spec), &mut buf);
                black_box(buf)
            })
        });
        grp.bench_function("host_glibc_inprocess", |b| {
            b.iter(|| {
                let mut buf = [0i8; 64];
                black_box(unsafe { strfromd(buf.as_mut_ptr(), 64, fmt.as_ptr(), black_box(value)) });
            })
        });
        grp.finish();
    }
}

criterion_group!(benches, bench, bench_deployed_e, bench_deployed_g, bench_diag_a);
criterion_main!(benches);
