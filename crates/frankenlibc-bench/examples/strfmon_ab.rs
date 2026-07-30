//! Mechanism test: does the time/locale generality tax generalize to `strfmon`?
//!
//! THE MECHANISM, stated so it can fail: glibc re-interprets a caller-supplied
//! specification on every call through a generic engine, so a specialized path that
//! matches the whole specification once and runs straight-line code wins in proportion
//! to how much per-call interpretation the API forces glibc to redo.
//!
//! WHY THIS FAMILY IS THE PREDICTION. `strfmon` is the most per-call-configurable
//! formatter in libc: each call interprets a format string AND performs full locale
//! monetary indirection — currency symbol, decimal point, thousands separator, the
//! grouping vector, sign position, and local-vs-international selection — before it
//! formats a single digit. If the mechanism is real rather than a lucky pocket in
//! time/locale, this is where it should show up largest outside that family.
//!
//! HOW IT FAILS. If glibc's monetary locale lookup is hoisted or cheap, the ratio sits
//! at or above 1.0 and the mechanism does NOT generalize on configurability alone —
//! which is a genuine result about the limits of the mechanism, not a null.
//!
//! Contract, identical in shape to the strptime/strftime harnesses that produced the
//! banked wins:
//!   1. line 1 is the SHA-256 of this binary, hashed by the binary itself.
//!   2. host glibc is held through `dlmopen(LM_ID_NEWLM)` — a fresh namespace that
//!      cannot resolve back to our own `no_mangle` exports. A plain `extern "C"` symbol
//!      in an abi-bench binary would silently measure fl against fl.
//!   3. both arms are pinned to the C locale in their OWN namespace — matched
//!      configuration is where cross-implementation comparisons usually die.
//!   4. every case runs a source-identical FL/FL null pair AND a glibc/glibc null pair,
//!      plus the FL/glibc effect pair, all in the SAME invocation with pair order
//!      alternating by sample. A ratio is reported as decisive only when BOTH nulls hold.
//!   5. bootstrap median CIs decide; the effect must clear 2x the larger null
//!      half-width and its CI must exclude 1.0. CV is telemetry and never gates.
//!   6. byte-identity is proven BEFORE timing: identical output bytes AND identical
//!      return value for every case.

use std::ffi::{c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUP: usize = 4;
const REPS: usize = 100_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;
const BUF: usize = 256;

type StrfmonFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> isize;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;

struct Case {
    label: &'static str,
    /// NUL-terminated monetary format.
    format: &'static [u8],
    value: f64,
    /// What a user would recognise this as.
    note: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "national",
        format: b"%n\0",
        value: 1_234_567.891,
        note: "the canonical call: national currency format, grouping-heavy value",
    },
    Case {
        label: "international",
        format: b"%i\0",
        value: 1_234_567.891,
        note: "international (ISO 4217) form of the same value",
    },
    Case {
        label: "precision_2",
        format: b"%.2n\0",
        value: 9_876.5,
        note: "explicit precision, the shape an invoice line uses",
    },
    Case {
        label: "width_16",
        format: b"%16n\0",
        value: 42.75,
        note: "right-aligned in a fixed column, the shape a statement uses",
    },
    Case {
        label: "no_grouping",
        format: b"%^n\0",
        value: 1_234_567.891,
        note: "grouping suppressed — isolates the grouping-vector walk",
    },
    Case {
        label: "paren_negative",
        format: b"%(n\0",
        value: -1_234.56,
        note: "accounting-style parenthesised negative",
    },
    Case {
        label: "two_values",
        format: b"%n %n\0",
        value: 1_234.56,
        note: "two conversions in one call — scales the per-directive term",
    },
];

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
    if values.len() % 2 == 0 {
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

#[inline(never)]
fn run_fl(buf: *mut c_char, fmt: *const c_char, value: f64) -> isize {
    let mut acc = 0isize;
    for _ in 0..REPS {
        let n = black_box(unsafe {
            frankenlibc_abi::unistd_abi::strfmon(
                black_box(buf),
                black_box(BUF),
                black_box(fmt),
                black_box(value),
            )
        });
        acc = acc.wrapping_add(n);
    }
    black_box(acc)
}

#[inline(never)]
fn run_host(host: StrfmonFn, buf: *mut c_char, fmt: *const c_char, value: f64) -> isize {
    let mut acc = 0isize;
    for _ in 0..REPS {
        let n = black_box(unsafe {
            host(
                black_box(buf),
                black_box(BUF),
                black_box(fmt),
                black_box(value),
            )
        });
        acc = acc.wrapping_add(n);
    }
    black_box(acc)
}

/// Conformance before timing: identical return value AND identical output bytes.
/// A faster formatter that differs on grouping, sign placement, or truncation is a
/// bug, not a win, so a mismatch aborts the run rather than being reported.
fn verify(host: StrfmonFn, case: &Case) {
    let mut fl_buf = [0i8; BUF];
    let mut host_buf = [0i8; BUF];
    let fmt = case.format.as_ptr().cast::<c_char>();

    let fl_n =
        unsafe { frankenlibc_abi::unistd_abi::strfmon(fl_buf.as_mut_ptr(), BUF, fmt, case.value) };
    let host_n = unsafe { host(host_buf.as_mut_ptr(), BUF, fmt, case.value) };

    assert_eq!(
        fl_n, host_n,
        "{}: return value differs (fl {fl_n} vs glibc {host_n})",
        case.label
    );
    if fl_n >= 0 {
        let n = fl_n as usize;
        let fl_bytes: Vec<u8> = fl_buf[..n].iter().map(|&b| b as u8).collect();
        let host_bytes: Vec<u8> = host_buf[..n].iter().map(|&b| b as u8).collect();
        assert_eq!(
            fl_bytes,
            host_bytes,
            "{}: output bytes differ (fl {:?} vs glibc {:?})",
            case.label,
            String::from_utf8_lossy(&fl_bytes),
            String::from_utf8_lossy(&host_bytes),
        );
    }
}

/// Also pin the truncation boundary, where a formatter is most likely to disagree.
fn verify_truncation(host: StrfmonFn) {
    let fmt = c"%n".as_ptr();
    for cap in 1..=24usize {
        let mut fl_buf = [0i8; BUF];
        let mut host_buf = [0i8; BUF];
        let fl_n = unsafe {
            frankenlibc_abi::unistd_abi::strfmon(fl_buf.as_mut_ptr(), cap, fmt, 1_234_567.891f64)
        };
        let host_n = unsafe { host(host_buf.as_mut_ptr(), cap, fmt, 1_234_567.891f64) };
        assert_eq!(
            fl_n, host_n,
            "truncation cap={cap}: return value differs (fl {fl_n} vs glibc {host_n})"
        );
        if fl_n >= 0 {
            let n = fl_n as usize;
            assert_eq!(
                &fl_buf[..n],
                &host_buf[..n],
                "truncation cap={cap}: output bytes differ"
            );
        }
    }
}

fn measure_case(host: StrfmonFn, case: &Case, host_label: &str) {
    let mut fl_buf = [0i8; BUF];
    let mut host_buf = [0i8; BUF];
    let fmt = case.format.as_ptr().cast::<c_char>();
    let value = case.value;

    let mut fl = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut fl_null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut fl_null_b = Vec::with_capacity(SAMPLES - WARMUP);
    let mut gl_null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut gl_null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        // FL/FL null.
        let start = Instant::now();
        black_box(run_fl(fl_buf.as_mut_ptr(), fmt, value));
        let fa = start.elapsed();
        let start = Instant::now();
        black_box(run_fl(fl_buf.as_mut_ptr(), fmt, value));
        let fb = start.elapsed();

        // glibc/glibc null — the incumbent arm gets its own null, so a ratio is
        // never attributed to us when the incumbent side is the unstable one.
        let start = Instant::now();
        black_box(run_host(host, host_buf.as_mut_ptr(), fmt, value));
        let ga = start.elapsed();
        let start = Instant::now();
        black_box(run_host(host, host_buf.as_mut_ptr(), fmt, value));
        let gb = start.elapsed();

        // Effect, order alternating by sample.
        let (fl_elapsed, glibc_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(fl_buf.as_mut_ptr(), fmt, value));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_host(host, host_buf.as_mut_ptr(), fmt, value));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_host(host, host_buf.as_mut_ptr(), fmt, value));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_buf.as_mut_ptr(), fmt, value));
            (start.elapsed(), b)
        };

        if sample >= WARMUP {
            let scale = REPS as f64;
            fl.push(fl_elapsed.as_nanos() as f64 / scale);
            glibc.push(glibc_elapsed.as_nanos() as f64 / scale);
            fl_null_a.push(fa.as_nanos() as f64 / scale);
            fl_null_b.push(fb.as_nanos() as f64 / scale);
            gl_null_a.push(ga.as_nanos() as f64 / scale);
            gl_null_b.push(gb.as_nanos() as f64 / scale);
        }
    }

    let effect: Vec<f64> = fl.iter().zip(&glibc).map(|(f, h)| f / h).collect();
    let fl_null: Vec<f64> = fl_null_b
        .iter()
        .zip(&fl_null_a)
        .map(|(b, a)| b / a)
        .collect();
    let gl_null: Vec<f64> = gl_null_b
        .iter()
        .zip(&gl_null_a)
        .map(|(b, a)| b / a)
        .collect();

    let effect_median = median(&effect);
    let (effect_low, effect_high) = bootstrap_median_ci95(&effect);
    let fl_null_median = median(&fl_null);
    let (fl_null_low, fl_null_high) = bootstrap_median_ci95(&fl_null);
    let gl_null_median = median(&gl_null);
    let (gl_null_low, gl_null_high) = bootstrap_median_ci95(&gl_null);

    let fl_hw = (1.0 - fl_null_low).abs().max((fl_null_high - 1.0).abs());
    let gl_hw = (1.0 - gl_null_low).abs().max((gl_null_high - 1.0).abs());
    let null_half_width = fl_hw.max(gl_hw);
    // Both nulls must themselves straddle 1.0, else neither arm is stable enough
    // to carry a ratio and the row is reported as null-violating.
    let fl_null_holds = fl_null_low <= 1.0 && fl_null_high >= 1.0;
    let gl_null_holds = gl_null_low <= 1.0 && gl_null_high >= 1.0;
    let nulls_hold = fl_null_holds && gl_null_holds;
    let clears_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let excludes_one = effect_high < 1.0 || effect_low > 1.0;

    let comparison = if !nulls_hold {
        "NULL_VIOLATED"
    } else if clears_null && excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if clears_null && excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "STRFMON case={} host={host_label} threads=1 samples={} reps/arm={REPS} \
         fl_median_ns={:.3} glibc_median_ns={:.3} note={}",
        case.label,
        fl.len(),
        median(&fl),
        median(&glibc),
        case.note,
    );
    println!(
        "STRFMON_CONTRACT case={} host={host_label} threads=1 kind=null_fl_fl \
         ratio_median={fl_null_median:.6} ratio_ci95=[{fl_null_low:.6},{fl_null_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6} null_holds={fl_null_holds}",
        case.label,
        cv_pct(&fl_null),
        median_absolute_deviation(&fl_null, fl_null_median),
    );
    println!(
        "STRFMON_CONTRACT case={} host={host_label} threads=1 kind=null_glibc_glibc \
         ratio_median={gl_null_median:.6} ratio_ci95=[{gl_null_low:.6},{gl_null_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6} null_holds={gl_null_holds}",
        case.label,
        cv_pct(&gl_null),
        median_absolute_deviation(&gl_null, gl_null_median),
    );
    println!(
        "STRFMON_CONTRACT case={} host={host_label} threads=1 kind=fl_glibc \
         ratio_median={effect_median:.6} ratio_ci95=[{effect_low:.6},{effect_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6} null_half_width={null_half_width:.6} \
         clears_2x_null={clears_null} nulls_hold={nulls_hold} comparison={comparison}",
        case.label,
        cv_pct(&effect),
        median_absolute_deviation(&effect, effect_median),
    );
}

fn host_identity() -> String {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let load = std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(","))
        .unwrap_or_else(|_| "unknown".into());
    format!("{hostname} cpus={cpus} loadavg={load}")
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    println!("HOST_IDENTITY {}", host_identity());

    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen(libc.so.6) failed");

    // Matched configuration: pin BOTH namespaces to the C locale explicitly.
    let host_setlocale: SetlocaleFn =
        unsafe { std::mem::transmute(libc::dlsym(handle, c"setlocale".as_ptr())) };
    let host_locale = unsafe { host_setlocale(libc::LC_ALL, c"C".as_ptr()) };
    assert!(
        !host_locale.is_null(),
        "incumbent setlocale(LC_ALL, C) failed"
    );
    let fl_locale = unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C".as_ptr()) };
    assert!(!fl_locale.is_null(), "fl setlocale(LC_ALL, C) failed");

    let sym = unsafe { libc::dlsym(handle, c"strfmon".as_ptr()) };
    assert!(!sym.is_null(), "dlsym(strfmon) failed");
    let host: StrfmonFn = unsafe { std::mem::transmute(sym) };

    // Record which object actually served the incumbent symbol, so the arm is
    // provably not our own no_mangle export.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let host_label = if unsafe { libc::dladdr(sym as *const c_void, &mut info) } != 0
        && !info.dli_fname.is_null()
    {
        unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }
            .to_string_lossy()
            .into_owned()
    } else {
        "unresolved".into()
    };
    println!("INCUMBENT_OBJECT {host_label}");

    for case in CASES {
        verify(host, case);
    }
    verify_truncation(host);
    println!(
        "verify: OK ({} cases byte-identical to host glibc, plus truncation caps 1..=24)",
        CASES.len()
    );

    for case in CASES {
        measure_case(host, case, &host_label);
    }
}
