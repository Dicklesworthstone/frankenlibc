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

use criterion::{Criterion, criterion_group, criterion_main};

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

    // Broad byte-identity fuzz vs glibc gcvt over random doubles × precisions —
    // guards the `format_fixed_from_sci` reposition (single-%e digits placed
    // around the point) against any divergence from glibc's %g, across the
    // fixed/scientific boundary and the rounding-carry edge. Deterministic LCG
    // (no Date/rand): mixes structured magnitudes and fully-random bit patterns.
    {
        let mut s: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            s
        };
        let mut checked = 0u64;
        for _ in 0..120_000 {
            let r = next();
            // Two value families: (a) a finite value from a random mantissa and a
            // bounded decimal-ish exponent; (b) a fully-random bit pattern.
            let v = if r & 1 == 0 {
                let mant = ((next() >> 11) as f64) / ((1u64 << 53) as f64); // [0,1)
                let e = (next() % 41) as i32 - 20; // 10^-20 .. 10^20
                let sign = if next() & 1 == 0 { 1.0 } else { -1.0 };
                sign * mant * 10f64.powi(e)
            } else {
                f64::from_bits(next())
            };
            if !v.is_finite() {
                continue;
            }
            let ndigit = 1 + (next() % 17) as i32;
            let mut flb = [0u8; 64];
            let nn = fl_gcvt(v, ndigit, &mut flb);
            let mut glb = [0i8; 64];
            unsafe { gcvt(v, ndigit as c_int, glb.as_mut_ptr()) };
            let gl: Vec<u8> = glb
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            assert_eq!(
                &flb[..nn],
                gl.as_slice(),
                "gcvt FUZZ mismatch: v={v:?} (bits={:#018x}) ndigit={ndigit} fl={:?} gl={:?}",
                v.to_bits(),
                String::from_utf8_lossy(&flb[..nn]),
                String::from_utf8_lossy(&gl)
            );
            checked += 1;
        }
        eprintln!("gcvt fuzz: {checked} random cases byte-identical to glibc");
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
                    gcvt(
                        black_box(*value),
                        black_box(*ndigit as c_int),
                        buf.as_mut_ptr(),
                    )
                });
            })
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
