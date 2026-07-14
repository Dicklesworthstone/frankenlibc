// fl f32 math vs glibc (dlmopen libm) — survey the hyperbolic/inverse-hyperbolic/
// special fns to find pure-`libm::*` (generic, slow) losses worth a fused-kernel port.
// Run: cargo run -p frankenlibc-abi --example math_survey --release
//
// MEASURED (cc, 2026-06-24): the f32 LOSSES vs glibc (all accurate, maxrel ~1e-7):
//   acoshf 2.03x, erfcf 1.94x, asinhf 1.92x, log1pf 1.71x, atanhf 1.65x  (clean targets);
//   tanhf 1.24x, sinhf 1.23x, expm1f 1.22x, coshf 1.13x, erff 1.08x      (minor).
// ROOT CAUSE (probed): asinhf/acoshf/atanhf are pure libm::*; rewriting each as one f64
// expression via fl's f64 `crate::math::log` is BIT-EXACT vs glibc (maxrel=0.00 — glibc
// uses the same f64-log identity) but ~2.1x (SLOWER than even libm's f32 path) because
// **fl's f64 `log` is itself ~2x slower than glibc's** (glibc's bit-identical asinhf is
// 5.7 ns; the fl version is ~12 ns, all in the f64 log). REVERTED (stash
// `cc-asinh-acosh-atanh-f64log-bitexact-but-slow-revert`). So the REAL high-leverage
// lever is a FUSED f64 `log` kernel (ARM optimized-routines / glibc __ieee754_log — the
// same method that landed f64 `pow` and the f32 powf/exp2f/log2f/expf/logf family) — it
// would fix log1pf + all three inverse hyperbolics at once. Multi-turn (f64 log is a
// core kernel used widely; needs ULP-conformance across its full gate). Alternatively a
// fast f32 `log1pf` (fl fused f32 `logf` + a small-|x| polynomial) fixes log1pf + the
// hyperbolics' small-arg ranges without touching f64 log.
//
// EXACT CODE-LEVEL ROOT CAUSE (cc, math/exp.rs:1063): fl's f64 `log(x) = log2_kernel(x)
// * LN_2` routes NATURAL log through the 64-bucket *log2* kernel (~9 ns, only glibc-LOG2
// parity) + a multiply; glibc's natural log is a DEDICATED 128-bucket `__log` (~5 ns).
// FIX = port ARM optimized-routines math/log.c + math/log_data.c, config N==128 /
// LOG_POLY_ORDER==6 (tab[128]{invc,logc} + tab2[128] + poly1[12] + poly[6] + ln2hi/lo),
// hex-floats via Python float.fromhex→from_bits, replacing the log2_kernel*LN_2
// indirection. A 2-3 turn core-function port (NOT a rush job); un-stash the bit-exact
// hyperbolics after.
use std::ffi::c_void;
use std::time::Instant;

type F32Fn = unsafe extern "C" fn(f32) -> f32;

type F64BinaryFn = unsafe extern "C" fn(f64, f64) -> f64;

fn median(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn time_atan2_axis(mut f: impl FnMut(f64, f64) -> f64, iterations: usize) -> f64 {
    let axes = [
        (0.0, 1.0),
        (-0.0, 2.0),
        (0.0, f64::MIN_POSITIVE),
        (-0.0, f64::INFINITY),
    ];
    let start = Instant::now();
    let mut bits = 0u64;
    for i in 0..iterations {
        let (y, x) = axes[i & 3];
        bits ^= f(std::hint::black_box(y), std::hint::black_box(x)).to_bits();
    }
    std::hint::black_box(bits);
    start.elapsed().as_nanos() as f64 / iterations as f64
}

fn time_atan2_general(mut f: impl FnMut(f64, f64) -> f64, iterations: usize) -> f64 {
    let general = [(0.25, 1.5), (-0.75, 2.25), (1.5, -0.5), (-2.0, -3.0)];
    let start = Instant::now();
    let mut sum = 0.0f64;
    for i in 0..iterations {
        let (y, x) = general[i & 3];
        sum += f(std::hint::black_box(y), std::hint::black_box(x));
    }
    std::hint::black_box(sum);
    start.elapsed().as_nanos() as f64 / iterations as f64
}

fn run_atan2_axis_ab() {
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libm.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen libm failed");
    let host: F64BinaryFn = unsafe {
        let symbol = libc::dlsym(handle, b"atan2\0".as_ptr().cast());
        assert!(!symbol.is_null(), "dlsym atan2 failed");
        std::mem::transmute(symbol)
    };

    let axes = [
        (0.0, 1.0),
        (-0.0, 2.0),
        (0.0, f64::MIN_POSITIVE),
        (-0.0, f64::INFINITY),
    ];
    for (y, x) in axes {
        let old = frankenlibc_abi::math_abi::bench_atan2_oldpath(y, x);
        let new = unsafe { frankenlibc_abi::math_abi::atan2(y, x) };
        let glibc = unsafe { host(y, x) };
        assert_eq!(
            new.to_bits(),
            old.to_bits(),
            "new/old mismatch at ({y}, {x})"
        );
        assert_eq!(
            new.to_bits(),
            glibc.to_bits(),
            "new/glibc mismatch at ({y}, {x})"
        );
    }
    let mut fallback_cases = 0usize;
    for i in 1..=1024 {
        let y = (i as f64).mul_add(0.001_953_125, -1.0);
        let x = (i as f64).mul_add(0.003_906_25, -1.5);
        if y != 0.0 && x != 0.0 {
            let old = frankenlibc_abi::math_abi::bench_atan2_oldpath(y, x);
            let new = unsafe { frankenlibc_abi::math_abi::atan2(y, x) };
            assert_eq!(
                new.to_bits(),
                old.to_bits(),
                "fallback mismatch at ({y}, {x})"
            );
            fallback_cases += 1;
        }
    }

    let iterations = 1_000_000usize;
    let mut old_axis = Vec::new();
    let mut new_axis = Vec::new();
    let mut host_axis = Vec::new();
    let mut old_control = Vec::new();
    let mut new_control = Vec::new();
    for sample in 0..60 {
        let mut push_old_axis = || {
            old_axis.push(time_atan2_axis(
                frankenlibc_abi::math_abi::bench_atan2_oldpath,
                iterations,
            ));
        };
        let mut push_new_axis = || {
            new_axis.push(time_atan2_axis(
                |y, x| unsafe { frankenlibc_abi::math_abi::atan2(y, x) },
                iterations,
            ));
        };
        let mut push_host_axis = || {
            host_axis.push(time_atan2_axis(|y, x| unsafe { host(y, x) }, iterations));
        };
        match sample % 3 {
            0 => {
                push_old_axis();
                push_new_axis();
                push_host_axis();
            }
            1 => {
                push_new_axis();
                push_host_axis();
                push_old_axis();
            }
            _ => {
                push_host_axis();
                push_old_axis();
                push_new_axis();
            }
        }

        if sample & 1 == 0 {
            old_control.push(time_atan2_general(
                frankenlibc_abi::math_abi::bench_atan2_oldpath,
                iterations,
            ));
            new_control.push(time_atan2_general(
                |y, x| unsafe { frankenlibc_abi::math_abi::atan2(y, x) },
                iterations,
            ));
        } else {
            new_control.push(time_atan2_general(
                |y, x| unsafe { frankenlibc_abi::math_abi::atan2(y, x) },
                iterations,
            ));
            old_control.push(time_atan2_general(
                frankenlibc_abi::math_abi::bench_atan2_oldpath,
                iterations,
            ));
        }
    }

    let (old_axis, new_axis, host_axis) =
        (median(&old_axis), median(&new_axis), median(&host_axis));
    let (old_control, new_control) = (median(&old_control), median(&new_control));
    println!("ATAN2_AXIS_EQ axis=4 fallback={fallback_cases} status=PASS");
    println!(
        "ATAN2_AXIS_AB old={old_axis:.2}ns new={new_axis:.2}ns host={host_axis:.2}ns new/old={:.3} new/host={:.3}",
        new_axis / old_axis,
        new_axis / host_axis,
    );
    println!(
        "ATAN2_GENERAL_NULL old={old_control:.2}ns new={new_control:.2}ns new/old={:.3}",
        new_control / old_control,
    );
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("atan2-axis-ab") {
        run_atan2_axis_ab();
        return;
    }

    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libm.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libm failed");
        let g = |n: &[u8]| -> F32Fn {
            let p = libc::dlsym(h, n.as_ptr().cast());
            assert!(!p.is_null(), "dlsym failed");
            std::mem::transmute::<*mut c_void, F32Fn>(p)
        };

        // (name, fl fn, glibc fn, input range lo, hi)
        let cases: &[(&str, F32Fn, F32Fn, f32, f32)] = &[
            (
                "asinhf",
                frankenlibc_abi::math_abi::asinhf,
                g(b"asinhf\0"),
                0.3,
                8.0,
            ),
            (
                "acoshf",
                frankenlibc_abi::math_abi::acoshf,
                g(b"acoshf\0"),
                1.1,
                8.0,
            ),
            (
                "atanhf",
                frankenlibc_abi::math_abi::atanhf,
                g(b"atanhf\0"),
                -0.9,
                0.9,
            ),
            (
                "sinhf",
                frankenlibc_abi::math_abi::sinhf,
                g(b"sinhf\0"),
                0.1,
                3.0,
            ),
            (
                "coshf",
                frankenlibc_abi::math_abi::coshf,
                g(b"coshf\0"),
                0.1,
                3.0,
            ),
            (
                "tanhf",
                frankenlibc_abi::math_abi::tanhf,
                g(b"tanhf\0"),
                0.1,
                4.0,
            ),
            (
                "erff",
                frankenlibc_abi::math_abi::erff,
                g(b"erff\0"),
                0.1,
                3.0,
            ),
            (
                "erfcf",
                frankenlibc_abi::math_abi::erfcf,
                g(b"erfcf\0"),
                0.1,
                6.0,
            ),
            (
                "expm1f",
                frankenlibc_abi::math_abi::expm1f,
                g(b"expm1f\0"),
                -1.0,
                2.0,
            ),
            (
                "log1pf",
                frankenlibc_abi::math_abi::log1pf,
                g(b"log1pf\0"),
                -0.5,
                4.0,
            ),
        ];

        // 4096 inputs spread over [lo,hi].
        let n = 30_000_000usize;
        for &(name, flf, glf, lo, hi) in cases {
            let xs: Vec<f32> = (0..4096)
                .map(|i| lo + (hi - lo) * (i as f32) / 4096.0)
                .collect();
            // accuracy: max abs-ULP-ish rel diff (sanity that fl ≈ glibc)
            let mut maxrel = 0.0f64;
            for &x in &xs {
                let a = flf(x) as f64;
                let b = glf(x) as f64;
                let d = if b.abs() > 1e-30 {
                    ((a - b) / b).abs()
                } else {
                    (a - b).abs()
                };
                if d > maxrel {
                    maxrel = d;
                }
            }
            let time = |f: F32Fn| -> f64 {
                let mut acc = 0.0f32;
                for k in 0..n {
                    acc += f(xs[k & 4095]);
                }
                std::hint::black_box(acc);
                let t = Instant::now();
                let mut acc = 0.0f32;
                for k in 0..n {
                    acc += f(xs[k & 4095]);
                }
                std::hint::black_box(acc);
                t.elapsed().as_nanos() as f64 / n as f64
            };
            let fl_ns = time(flf);
            let gl_ns = time(glf);
            println!(
                "MATH_SURVEY {name:8} fl={fl_ns:6.2}ns glibc={gl_ns:6.2}ns fl/glibc={:.2}x maxrel={maxrel:.2e}",
                fl_ns / gl_ns
            );
        }

        // f64 `log` direct (the core kernel this port replaces).
        type F64Fn = unsafe extern "C" fn(f64) -> f64;
        let gl_log: F64Fn =
            std::mem::transmute::<*mut c_void, F64Fn>(libc::dlsym(h, b"log\0".as_ptr().cast()));
        let xs: Vec<f64> = (0..4096)
            .map(|i| 0.2 + 50.0 * (i as f64) / 4096.0)
            .collect();
        let mut maxrel = 0.0f64;
        for &x in &xs {
            let a = frankenlibc_abi::math_abi::log(x);
            let b = gl_log(x);
            let d = ((a - b) / b).abs();
            if d > maxrel {
                maxrel = d;
            }
        }
        let time64 = |f: F64Fn| -> f64 {
            let mut acc = 0.0f64;
            for k in 0..30_000_000usize {
                acc += f(xs[k & 4095]);
            }
            std::hint::black_box(acc);
            let t = Instant::now();
            let mut acc = 0.0f64;
            for k in 0..30_000_000usize {
                acc += f(xs[k & 4095]);
            }
            std::hint::black_box(acc);
            t.elapsed().as_nanos() as f64 / 30_000_000.0
        };
        let fl_ns = time64(frankenlibc_abi::math_abi::log);
        let gl_ns = time64(gl_log);
        println!(
            "MATH_SURVEY log(f64) fl={fl_ns:6.2}ns glibc={gl_ns:6.2}ns fl/glibc={:.2}x maxrel={maxrel:.2e}",
            fl_ns / gl_ns
        );

        // f64 `log10` (its hot path now rides the fast __log kernel).
        let gl_log10: F64Fn =
            std::mem::transmute::<*mut c_void, F64Fn>(libc::dlsym(h, b"log10\0".as_ptr().cast()));
        let mut maxrel = 0.0f64;
        for &x in &xs {
            let a = frankenlibc_abi::math_abi::log10(x);
            let b = gl_log10(x);
            let d = ((a - b) / b).abs();
            if d > maxrel {
                maxrel = d;
            }
        }
        let fl_ns = time64(frankenlibc_abi::math_abi::log10);
        let gl_ns = time64(gl_log10);
        println!(
            "MATH_SURVEY log10(f64) fl={fl_ns:6.2}ns glibc={gl_ns:6.2}ns fl/glibc={:.2}x maxrel={maxrel:.2e}",
            fl_ns / gl_ns
        );

        // f64 transform/special fns — find the next log10-style win.
        let f64cases: &[(&str, F64Fn, F64Fn, f64, f64)] = &[
            (
                "log1p",
                frankenlibc_abi::math_abi::log1p,
                g64(h, b"log1p\0"),
                0.1,
                30.0,
            ),
            (
                "exp10",
                frankenlibc_abi::math_abi::exp10,
                g64(h, b"exp10\0"),
                -2.0,
                3.0,
            ),
            (
                "erfc",
                frankenlibc_abi::math_abi::erfc,
                g64(h, b"erfc\0"),
                0.1,
                5.0,
            ),
            (
                "tgamma",
                frankenlibc_abi::math_abi::tgamma,
                g64(h, b"tgamma\0"),
                0.5,
                8.0,
            ),
            (
                "lgamma",
                frankenlibc_abi::math_abi::lgamma,
                g64(h, b"lgamma\0"),
                0.5,
                12.0,
            ),
            (
                "exp",
                frankenlibc_abi::math_abi::exp,
                g64(h, b"exp\0"),
                -20.0,
                20.0,
            ),
            (
                "exp2",
                frankenlibc_abi::math_abi::exp2,
                g64(h, b"exp2\0"),
                -20.0,
                20.0,
            ),
            (
                "expm1",
                frankenlibc_abi::math_abi::expm1,
                g64(h, b"expm1\0"),
                -1.5,
                3.0,
            ),
            (
                "cbrt",
                frankenlibc_abi::math_abi::cbrt,
                g64(h, b"cbrt\0"),
                0.1,
                100.0,
            ),
            (
                "sinh",
                frankenlibc_abi::math_abi::sinh,
                g64(h, b"sinh\0"),
                0.1,
                3.0,
            ),
            (
                "cosh",
                frankenlibc_abi::math_abi::cosh,
                g64(h, b"cosh\0"),
                0.1,
                3.0,
            ),
            (
                "tanhd",
                frankenlibc_abi::math_abi::tanh,
                g64(h, b"tanh\0"),
                0.05,
                25.0,
            ),
            (
                "asinhd",
                frankenlibc_abi::math_abi::asinh,
                g64(h, b"asinh\0"),
                0.2,
                1.0e7,
            ),
            (
                "acoshd",
                frankenlibc_abi::math_abi::acosh,
                g64(h, b"acosh\0"),
                1.05,
                1.0e7,
            ),
            (
                "atanhd",
                frankenlibc_abi::math_abi::atanh,
                g64(h, b"atanh\0"),
                -0.95,
                0.95,
            ),
            (
                "sind",
                frankenlibc_abi::math_abi::sin,
                g64(h, b"sin\0"),
                -3.1,
                3.1,
            ),
            (
                "cosd",
                frankenlibc_abi::math_abi::cos,
                g64(h, b"cos\0"),
                -3.1,
                3.1,
            ),
            (
                "tand",
                frankenlibc_abi::math_abi::tan,
                g64(h, b"tan\0"),
                -1.5,
                1.5,
            ),
            (
                "logd",
                frankenlibc_abi::math_abi::log,
                g64(h, b"log\0"),
                0.2,
                50.0,
            ),
            (
                "sqrtd",
                frankenlibc_abi::math_abi::sqrt,
                g64(h, b"sqrt\0"),
                0.1,
                1.0e6,
            ),
            (
                "atand",
                frankenlibc_abi::math_abi::atan,
                g64(h, b"atan\0"),
                -8.0,
                8.0,
            ),
            (
                "asind",
                frankenlibc_abi::math_abi::asin,
                g64(h, b"asin\0"),
                -0.95,
                0.95,
            ),
            (
                "acosd",
                frankenlibc_abi::math_abi::acos,
                g64(h, b"acos\0"),
                -0.95,
                0.95,
            ),
            (
                "cbrtd",
                frankenlibc_abi::math_abi::cbrt,
                g64(h, b"cbrt\0"),
                0.1,
                1.0e6,
            ),
        ];
        for &(name, flf, glf, lo, hi) in f64cases {
            let xs: Vec<f64> = (0..4096)
                .map(|i| lo + (hi - lo) * (i as f64) / 4096.0)
                .collect();
            let mut maxrel = 0.0f64;
            for &x in &xs {
                let a = flf(x);
                let b = glf(x);
                let d = if b.abs() > 1e-290 {
                    ((a - b) / b).abs()
                } else {
                    (a - b).abs()
                };
                if d > maxrel {
                    maxrel = d;
                }
            }
            let t = |f: F64Fn| -> f64 {
                let mut acc = 0.0f64;
                for k in 0..20_000_000usize {
                    acc += f(xs[k & 4095]);
                }
                std::hint::black_box(acc);
                let s = Instant::now();
                let mut acc = 0.0f64;
                for k in 0..20_000_000usize {
                    acc += f(xs[k & 4095]);
                }
                std::hint::black_box(acc);
                s.elapsed().as_nanos() as f64 / 20_000_000.0
            };
            let (fl_ns, gl_ns) = (t(flf), t(glf));
            println!(
                "MATH_SURVEY {name:8} fl={fl_ns:6.2}ns glibc={gl_ns:6.2}ns fl/glibc={:.2}x maxrel={maxrel:.2e}",
                fl_ns / gl_ns
            );
        }

        // Full-range ULP sweep of f64 exp vs glibc over the entire finite-result domain
        // [-708, 709] — validates the widened compensated path at the extremes (where the
        // old [-5,5] limit was conservative). ULP = |fl_bits - glibc_bits| (exp > 0).
        let gl_exp: F64Fn =
            std::mem::transmute::<*mut c_void, F64Fn>(libc::dlsym(h, b"exp\0".as_ptr().cast()));
        let mut max_ulp = 0i64;
        let mut worst_x = 0.0f64;
        let n = 4_000_000usize;
        for i in 0..n {
            let x = -708.0 + (709.0 - (-708.0)) * (i as f64) / (n as f64);
            let a = frankenlibc_abi::math_abi::exp(x).to_bits() as i64;
            let b = gl_exp(x).to_bits() as i64;
            let u = (a - b).abs();
            if u > max_ulp {
                max_ulp = u;
                worst_x = x;
            }
        }
        println!("MATH_SURVEY exp_ULP_sweep [-708,709] max_ulp={max_ulp} at x={worst_x:.4}");

        // Complex csinh: now shares ONE exp(rx) for rx in [1,700) (was sinh+cosh = 2 exp).
        // In-process A/B vs glibc (load cancels in the ratio). re in [1,10), im in [0.5,3).
        use frankenlibc_abi::math_abi::{CDoubleComplex, csinh};
        type CFn = unsafe extern "C" fn(CDoubleComplex) -> CDoubleComplex;
        let gl_csinh: CFn =
            std::mem::transmute::<*mut c_void, CFn>(libc::dlsym(h, b"csinh\0".as_ptr().cast()));
        let cin: Vec<CDoubleComplex> = (0..1000)
            .map(|k| CDoubleComplex {
                re: 1.0 + (k as f64) * 0.009,
                im: 0.5 + ((k % 250) as f64) * 0.01,
            })
            .collect();
        let iters = 3000usize;
        for z in &cin {
            std::hint::black_box(csinh(std::hint::black_box(*z)));
            std::hint::black_box(gl_csinh(std::hint::black_box(*z)));
        }
        let t0 = Instant::now();
        for _ in 0..iters {
            for z in &cin {
                std::hint::black_box(csinh(std::hint::black_box(*z)));
            }
        }
        let fl_ns = t0.elapsed().as_nanos() as f64 / (iters * cin.len()) as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            for z in &cin {
                std::hint::black_box(gl_csinh(std::hint::black_box(*z)));
            }
        }
        let gl_ns = t1.elapsed().as_nanos() as f64 / (iters * cin.len()) as f64;
        println!(
            "MATH_SURVEY csinh_complex fl={fl_ns:.2}ns glibc={gl_ns:.2}ns fl/glibc={:.2}x",
            fl_ns / gl_ns
        );
    }
}

unsafe fn g64(h: *mut std::ffi::c_void, n: &[u8]) -> unsafe extern "C" fn(f64) -> f64 {
    let p = libc::dlsym(h, n.as_ptr().cast());
    assert!(!p.is_null(), "dlsym f64 failed");
    std::mem::transmute::<*mut std::ffi::c_void, unsafe extern "C" fn(f64) -> f64>(p)
}
