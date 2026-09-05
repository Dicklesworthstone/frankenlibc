//! Direct live-glibc A/B for the f32 hyperbolics `sinhf` / `coshf` (bd-rdhdeq).
//!
//! # THIS FILE HAS NEVER PRODUCED A ROW. DO NOT CITE IT AS EVIDENCE.
//!
//! Landed deliberately in an unexecuted state so the next person starts from an
//! instrument instead of a blank file, and the exact limit of what has been
//! observed is this:
//!
//!   * it COMPILES and LINKS in `--release` with `--features abi-bench`, and the
//!     binary starts: one run on rch worker ovh-a printed `BENCH_ELF_SHA256`,
//!     `ISA_PROVENANCE` and `HOST_IDENTITY`, then entered the host-wide quiet
//!     guard on a contended 16-CPU shared worker and died there without a
//!     terminal line;
//!   * a second run pinned to vmi1227854 with `--case hot` died during the cold
//!     release build, also without a terminal line.
//!
//! So `verify()` and `measure_case()` below have NEVER RUN. The dlsym collapse
//! guard, the ULP sweep and the statistics are unexecuted code. Treat the first
//! successful run as a debugging session, not as a measurement, and do not put
//! any number this file prints into the ledger until it has run clean twice.
//!
//! One design change was already made in response to the first failure: `verify()`
//! now runs BEFORE the quiet guard is even constructed, because accuracy does not
//! depend on an idle host and the first run yielded nothing at all — not even
//! "fl is within 4 ULP" — by gating correctness behind quiescence.
//!
//! ## Why this exists rather than another `--family sinhf_coshf` attempt
//!
//! bd-rdhdeq's harness is `incumbent_coverage_ab --family sinhf_coshf`, and that
//! path has failed to return a verdict for five agents across three beads:
//! a job that vanished during an rch daemon restart, a run whose `coshf` cell was
//! invalidated by an A/A null of 1.027075, a differential gate that hung silently
//! for seven minutes, and a run that built cleanly and then sat over an hour past
//! `Running` before being cancelled. Meanwhile the DIRECT `*_ab` examples return:
//! `strftime_litrun_ab` produced complete rows three times on 2026-09-01 in about
//! 180 s each.
//!
//! So this file is deliberately the same shape as `strftime_litrun_ab` — the
//! statistical scaffolding below is its scaffolding — applied to the surface
//! bd-rdhdeq needs measured. Each case is a same-invocation FL/glibc effect pair
//! against a source-identical FL/FL null, pair order alternating by sample,
//! bootstrap median CIs, and the 2x-null rule deciding. CV is descriptive only.
//!
//! ## What it is measuring
//!
//! `float32.rs::sinhf`/`coshf` promote to f64 and run fl's f64 kernel:
//!
//!     pub fn sinhf(x: f32) -> f32 { crate::math::sinh(x as f64) as f32 }
//!
//! and on `|x| <= 3` that kernel is a THIRTEEN-step serial Horner chain
//! (`trig.rs::sinh_poly_le_3`, odd Taylor through x^27). Horner is a strict
//! dependency chain, so those FMAs cannot overlap. The cases below are chosen to
//! separate that band from the paths around it, because "sinhf is 2.26x slower"
//! does not say WHICH path is slow:
//!
//!   * `small`  — well inside the polynomial band, no `exp` anywhere;
//!   * `hot`    — the band the campaign times, still polynomial;
//!   * `edge`   — just under 3, the last polynomial input;
//!   * `reroute`— just over 3, where fl leaves the polynomial for `(t±1/t)/2`
//!                with `t = exp(|x|)`. If fl's loss is concentrated here instead,
//!                the fix is not a shorter polynomial at all.
//!
//! Accuracy is checked against live glibc BEFORE any timing, because bd-rdhdeq's
//! negative case is that a faster kernel must keep the specials bit-exact and stay
//! inside 4 ULP — a timing row for a kernel that lost accuracy is worthless.

use std::ffi::{c_char, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_bench::HostWideBenchmarkGuard;
use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUP: usize = 4;
const REPS: usize = 400_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;

type Unaryf = unsafe extern "C" fn(f32) -> f32;

fn host_wide_guard() -> HostWideBenchmarkGuard {
    HostWideBenchmarkGuard::new().unwrap_or_else(|error| {
        eprintln!("BENCH_HOST_WIDE_EXCLUSIVITY phase=initialize verdict=BLOCKED reason={error:?}");
        std::process::exit(2);
    })
}

fn require_host_wide_quiet(guard: &HostWideBenchmarkGuard, phase: &str) {
    match guard.check_quiet() {
        Ok(evidence) => println!("{}", evidence.contract_line(phase)),
        Err(error) => {
            eprintln!("BENCH_HOST_WIDE_EXCLUSIVITY phase={phase} verdict=BLOCKED reason={error:?}");
            std::process::exit(2);
        }
    }
}

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".into();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".into();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut digest_hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest_hex, "{byte:02x}").expect("write SHA-256 hex");
    }
    format!("{} ({} bytes) {}", digest_hex, bytes.len(), path.display())
}

fn median(xs: &[f64]) -> f64 {
    let mut values = xs.to_vec();
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn cv_pct(xs: &[f64]) -> f64 {
    let avg = mean(xs);
    let variance = xs.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / xs.len() as f64;
    100.0 * variance.sqrt() / avg
}

fn median_absolute_deviation(xs: &[f64], center: f64) -> f64 {
    median(&xs.iter().map(|v| (v - center).abs()).collect::<Vec<_>>())
}

fn bootstrap_median_ci95(xs: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ xs.len() as u64;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; xs.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = xs[(state as usize) % xs.len()];
        }
        medians.push(median(&resample));
    }
    medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (medians[low], medians[high])
}

/// Run `f` over the case's inputs `repetitions` times.
///
/// The inputs are a small array walked cyclically rather than one constant, so
/// the measurement cannot be a single memoised value or a branch predictor that
/// has learned one path — while staying inside the band the case names.
#[inline(never)]
fn run_arm(f: Unaryf, inputs: &[f32], repetitions: usize) -> f32 {
    let mut acc = 0.0f32;
    for i in 0..repetitions {
        // SAFETY: both arms are plain `extern "C" fn(f32) -> f32`.
        acc += black_box(unsafe { f(black_box(inputs[i % inputs.len()])) });
    }
    black_box(acc)
}

struct Case {
    label: &'static str,
    inputs: &'static [f32],
}

const CASES: &[Case] = &[
    // Inside the polynomial band, small enough that the series converges fast.
    Case {
        label: "small",
        inputs: &[0.03125, 0.125, 0.25, 0.5, 0.75, 0.9],
    },
    // The band bd-rdhdeq's campaign times.
    Case {
        label: "hot",
        inputs: &[0.1, 0.6, 1.1, 1.7, 2.2, 2.8],
    },
    // The last inputs still taking `*_poly_le_3`.
    Case {
        label: "edge",
        inputs: &[2.90625, 2.9375, 2.96875, 2.984_375, 2.992_187_5, 2.999],
    },
    // Just past the cutoff: fl leaves the polynomial for (t±1/t)/2, t = exp(|x|).
    // If the loss lives here rather than in `hot`, a shorter polynomial is the
    // wrong fix and this case is what says so.
    Case {
        label: "reroute",
        inputs: &[3.03125, 3.25, 3.75, 4.5, 5.5, 6.75],
    },
];

/// Compare fl against live glibc before timing anything.
///
/// bd-rdhdeq's stated negative case is that a faster kernel must keep the
/// specials bit-exact and stay within 4 ULP. This runs first so a kernel that
/// bought speed with accuracy cannot produce a timing row at all.
fn verify(name: &str, fl: Unaryf, host: Unaryf) {
    let mut compared = 0usize;
    let mut worst_ulp = 0i64;

    // Specials must be bit-identical, sign included.
    for &x in &[
        0.0f32,
        -0.0,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
        -f32::NAN,
        f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE,
    ] {
        // SAFETY: plain unary f32 calls into both impls.
        let (f, g) = unsafe { (fl(x), host(x)) };
        if x.is_nan() {
            assert!(
                f.is_nan() && g.is_nan(),
                "{name}({x}) special NaN mismatch: fl={f} glibc={g}"
            );
        } else {
            assert_eq!(
                f.to_bits(),
                g.to_bits(),
                "{name}({x}) special not bit-exact: fl={f} ({:#010x}) glibc={g} ({:#010x})",
                f.to_bits(),
                g.to_bits(),
            );
        }
        compared += 1;
    }

    // Dense sweep across the polynomial band, its edge, and the reroute.
    for step in 0..=2048u32 {
        let x = -7.0f32 + (14.0 * f32::from(step as u16) / 2048.0);
        for &x in &[x, -x] {
            if !x.is_finite() {
                continue;
            }
            // SAFETY: as above.
            let (f, g) = unsafe { (fl(x), host(x)) };
            if f.is_nan() && g.is_nan() {
                continue;
            }
            let ulp = (f.to_bits() as i64 - g.to_bits() as i64).abs();
            worst_ulp = worst_ulp.max(ulp);
            assert!(
                ulp <= 4,
                "{name}({x}) is {ulp} ULP from glibc: fl={f} glibc={g}"
            );
            compared += 1;
        }
    }
    println!(
        "HYPERBOLICF_ACCURACY fn={name} comparisons={compared} worst_ulp={worst_ulp} \
         specials_bit_exact=true limit_ulp=4 verdict=pass"
    );
}

fn measure_case(name: &str, fl: Unaryf, host: Unaryf, case: &Case, repetitions: usize) {
    let mut fl_ns = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc_ns = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        // Source-identical FL/FL null, order alternating with the sample.
        let (a, b) = if sample % 2 == 0 {
            let s = Instant::now();
            black_box(run_arm(fl, case.inputs, repetitions));
            let a = s.elapsed();
            let s = Instant::now();
            black_box(run_arm(fl, case.inputs, repetitions));
            (a, s.elapsed())
        } else {
            let s = Instant::now();
            black_box(run_arm(fl, case.inputs, repetitions));
            let b = s.elapsed();
            let s = Instant::now();
            black_box(run_arm(fl, case.inputs, repetitions));
            (s.elapsed(), b)
        };

        // FL/glibc effect, order alternating the other way round.
        let (f, g) = if sample % 2 == 0 {
            let s = Instant::now();
            black_box(run_arm(fl, case.inputs, repetitions));
            let f = s.elapsed();
            let s = Instant::now();
            black_box(run_arm(host, case.inputs, repetitions));
            (f, s.elapsed())
        } else {
            let s = Instant::now();
            black_box(run_arm(host, case.inputs, repetitions));
            let g = s.elapsed();
            let s = Instant::now();
            black_box(run_arm(fl, case.inputs, repetitions));
            (s.elapsed(), g)
        };

        if sample >= WARMUP {
            let scale = repetitions as f64;
            fl_ns.push(f.as_nanos() as f64 / scale);
            glibc_ns.push(g.as_nanos() as f64 / scale);
            null_a.push(a.as_nanos() as f64 / scale);
            null_b.push(b.as_nanos() as f64 / scale);
        }
    }

    let effect = fl_ns
        .iter()
        .zip(&glibc_ns)
        .map(|(f, g)| f / g)
        .collect::<Vec<_>>();
    let null = null_b
        .iter()
        .zip(&null_a)
        .map(|(b, a)| b / a)
        .collect::<Vec<_>>();
    let effect_median = median(&effect);
    let null_median = median(&null);
    let (effect_low, effect_high) = bootstrap_median_ci95(&effect);
    let (null_low, null_high) = bootstrap_median_ci95(&null);
    let null_half_width = (1.0 - null_low).abs().max((null_high - 1.0).abs());
    let clears_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let excludes_one = effect_high < 1.0 || effect_low > 1.0;
    let comparison = if clears_null && excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if clears_null && excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "HYPERBOLICF fn={name} case={} samples={} reps/arm={repetitions} \
         fl_median_ns={:.3} glibc_median_ns={:.3}",
        case.label,
        fl_ns.len(),
        median(&fl_ns),
        median(&glibc_ns),
    );
    println!(
        "HYPERBOLICF_CONTRACT fn={name} case={} kind=null_fl_fl \
         ratio_median={null_median:.6} ratio_ci95=[{null_low:.6},{null_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6}",
        case.label,
        cv_pct(&null),
        median_absolute_deviation(&null, null_median),
    );
    println!(
        "HYPERBOLICF_CONTRACT fn={name} case={} kind=fl_glibc \
         ratio_median={effect_median:.6} ratio_ci95=[{effect_low:.6},{effect_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6} null_half_width={null_half_width:.6} \
         clears_2x_null={clears_null} comparison={comparison}",
        case.label,
        cv_pct(&effect),
        median_absolute_deviation(&effect, effect_median),
    );
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    println!(
        "ISA_PROVENANCE built_avx2={} built_fma={} built_sse42={} \
         cpu_avx2={} cpu_avx512f={} cpu_sse42={}",
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        cfg!(target_feature = "sse4.2"),
        std::arch::is_x86_feature_detected!("avx2"),
        std::arch::is_x86_feature_detected!("avx512f"),
        std::arch::is_x86_feature_detected!("sse4.2"),
    );
    println!(
        "HOST_IDENTITY {} cpus={} loadavg={}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        std::fs::read_to_string("/proc/loadavg")
            .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(","))
            .unwrap_or_else(|_| "unknown".into()),
    );

    // The incumbent is resolved in a FRESH link namespace, not by a link-time
    // `extern` — fl exports `sinhf`/`coshf` under
    // `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, so in this release
    // build a plain extern reference would bind to fl's own definition and the
    // benchmark would time fl against fl and report parity.
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libm.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    let handle = if handle.is_null() {
        // Modern glibc folds libm into libc.so.6; older layouts keep it split.
        unsafe {
            libc::dlmopen(
                libc::LM_ID_NEWLM,
                c"libc.so.6".as_ptr(),
                libc::RTLD_LAZY | libc::RTLD_LOCAL,
            )
        }
    } else {
        handle
    };
    assert!(
        !handle.is_null(),
        "dlmopen of libm.so.6 and libc.so.6 failed"
    );

    let resolve = |name: &std::ffi::CStr, fl_addr: *const ()| -> Unaryf {
        let raw = unsafe { libc::dlsym(handle, name.as_ptr().cast::<c_char>()) };
        assert!(!raw.is_null(), "dlsym({name:?}) found nothing");
        assert!(
            !std::ptr::eq(raw.cast::<()>(), fl_addr),
            "dlsym({name:?}) returned fl's OWN export -- the incumbent arm collapsed"
        );
        // SAFETY: the symbol is glibc's `float (*)(float)`.
        unsafe { std::mem::transmute::<*mut c_void, Unaryf>(raw) }
    };

    let fl_sinhf: Unaryf = frankenlibc_abi::math_abi::sinhf;
    let fl_coshf: Unaryf = frankenlibc_abi::math_abi::coshf;
    let host_sinhf = resolve(c"sinhf", fl_sinhf as *const ());
    let host_coshf = resolve(c"coshf", fl_coshf as *const ());

    // ACCURACY FIRST, BEFORE THE QUIET GUARD IS EVEN CONSTRUCTED. Correctness
    // does not depend on the host being idle, and putting the guard first means
    // a contended worker yields NOTHING -- not even "fl is within 4 ULP" -- which
    // is what the first run of this file did: it printed its three provenance
    // lines, entered the startup guard on a busy 16-CPU shared worker, and died
    // without ever reaching the comparison. A run that cannot time can still
    // adjudicate, so it should.
    verify("sinhf", fl_sinhf, host_sinhf);
    verify("coshf", fl_coshf, host_coshf);

    let host_guard = host_wide_guard();
    require_host_wide_quiet(&host_guard, "startup");

    let mut selected: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--case" => selected = Some(args.next().expect("--case requires a label")),
            other => panic!("unknown argument: {other}"),
        }
    }
    let cases = CASES
        .iter()
        .filter(|c| selected.as_deref().is_none_or(|l| c.label == l))
        .collect::<Vec<_>>();
    assert!(!cases.is_empty(), "no case matched {selected:?}");

    for (name, fl, host) in [
        ("sinhf", fl_sinhf, host_sinhf),
        ("coshf", fl_coshf, host_coshf),
    ] {
        for case in &cases {
            let phase = format!("pre_{name}_{}", case.label);
            require_host_wide_quiet(&host_guard, &phase);
            measure_case(name, fl, host, case, REPS);
            let phase = format!("post_{name}_{}", case.label);
            require_host_wide_quiet(&host_guard, &phase);
        }
    }
}
