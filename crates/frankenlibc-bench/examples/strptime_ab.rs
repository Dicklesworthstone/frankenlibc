//! First vs-glibc measurement of `strptime` — the PARSE direction.
//!
//! `strptime` is implemented, exported and conformance-tested, and has never once been
//! measured against the incumbent. Fleet finding 2026-07-28: frankensearch shipped ~90
//! commits behind ten gates that all read `unmeasured`, and its first real gate came
//! back **8.7x SLOWER** than the incumbent. Believing a surface is fast is not the same
//! as knowing it, so this measures before anything is built on top of it.
//!
//! Contract, identical to `strftime_litrun_ab`:
//!   1. line 1 is the SHA-256 of this binary, hashed by the binary itself.
//!   2. host glibc is held through `dlmopen(LM_ID_NEWLM)` — a fresh namespace that
//!      cannot resolve back to our own `no_mangle` exports. A plain `extern "C"` symbol
//!      in an abi-bench binary would silently measure fl against fl.
//!   3. every case runs a source-identical FL/FL null pair and an FL/glibc effect pair
//!      IN THE SAME INVOCATION, pair order alternating by sample.
//!   4. bootstrap median CIs decide; the effect must clear 2x the null half-width and
//!      its CI must exclude 1.0. CV is printed as telemetry and never gates.
//!   5. behavior parity is proven before timing: both sides must agree on the returned
//!      end pointer offset AND on every `tm` field the format sets.

use std::ffi::c_char;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_bench::HostWideBenchmarkGuard;
use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUP: usize = 4;
const REPS: usize = 150_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;

type StrptimeFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char;

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

struct Case {
    label: &'static str,
    /// NUL-terminated input to parse.
    input: &'static [u8],
    /// NUL-terminated format.
    format: &'static [u8],
}

const CASES: &[Case] = &[
    // The parse-direction analogues of the formats that won on the emit side.
    Case {
        label: "iso_date",
        input: b"2023-11-14\0",
        format: b"%Y-%m-%d\0",
    },
    Case {
        label: "hms",
        input: b"22:13:20\0",
        format: b"%H:%M:%S\0",
    },
    Case {
        label: "iso_datetime",
        input: b"2023-11-14 22:13:20\0",
        format: b"%Y-%m-%d %H:%M:%S\0",
    },
    // Whole-format aliases: on the emit side these missed every leaf and lost 3.44x
    // until normalized. Does the parse side have the same shape?
    Case {
        label: "alias_T",
        input: b"22:13:20\0",
        format: b"%T\0",
    },
    Case {
        label: "alias_F",
        input: b"2023-11-14\0",
        format: b"%F\0",
    },
    // Month/weekday NAME parsing — a table lookup on both sides, and the place a
    // locale-generic implementation pays most.
    Case {
        label: "month_name",
        input: b"Nov 14 2023\0",
        format: b"%b %d %Y\0",
    },
    // HTTP-date, RFC 7231. Parsing `Date:` headers is one of the most executed
    // strptime calls in production code.
    Case {
        label: "http_date",
        input: b"Tue, 14 Nov 2023 22:13:20 GMT\0",
        format: b"%a, %d %b %Y %H:%M:%S GMT\0",
    },
    // syslog RFC 3164.
    Case {
        label: "syslog_ts",
        input: b"Nov 14 22:13:20\0",
        format: b"%b %e %H:%M:%S\0",
    },
    // Timestamp prefix from Apache's Combined Log Format. This adds the
    // month-name and numeric-zone genericity taxes to a complete real format.
    Case {
        label: "apache_combined_log",
        input: b"[14/Nov/2023:22:13:20 +0000]\0",
        format: b"[%d/%b/%Y:%H:%M:%S %z]\0",
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

#[inline(never)]
fn run_fl(input: *const c_char, fmt: *const c_char, tm: *mut libc::tm) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        let end = black_box(unsafe {
            frankenlibc_abi::time_abi::strptime(black_box(input), black_box(fmt), black_box(tm))
        });
        total = total.wrapping_add(end as usize);
    }
    black_box(total)
}

#[inline(never)]
fn run_host(
    host: StrptimeFn,
    input: *const c_char,
    fmt: *const c_char,
    tm: *mut libc::tm,
) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        let end = black_box(unsafe { host(black_box(input), black_box(fmt), black_box(tm)) });
        total = total.wrapping_add(end as usize);
    }
    black_box(total)
}

/// Behavior parity before timing: same consumed-prefix length, and same value in every
/// `tm` field either side sets. Compared field-by-field rather than by struct equality
/// because glibc leaves untouched fields alone and the two may differ in padding.
fn verify(host: StrptimeFn, case: &Case) {
    let input = case.input.as_ptr().cast::<c_char>();
    let fmt = case.format.as_ptr().cast::<c_char>();

    let mut fl_tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut host_tm: libc::tm = unsafe { std::mem::zeroed() };

    let fl_end = unsafe { frankenlibc_abi::time_abi::strptime(input, fmt, &mut fl_tm) };
    let host_end = unsafe { host(input, fmt, &mut host_tm) };

    assert_eq!(
        fl_end.is_null(),
        host_end.is_null(),
        "{}: null-ness of returned end pointer differs (fl {:?} vs glibc {:?})",
        case.label,
        fl_end,
        host_end
    );

    if !fl_end.is_null() {
        let fl_consumed = fl_end as usize - input as usize;
        let host_consumed = host_end as usize - input as usize;
        assert_eq!(
            fl_consumed, host_consumed,
            "{}: consumed prefix length differs",
            case.label
        );

        for (name, a, b) in [
            ("tm_sec", fl_tm.tm_sec, host_tm.tm_sec),
            ("tm_min", fl_tm.tm_min, host_tm.tm_min),
            ("tm_hour", fl_tm.tm_hour, host_tm.tm_hour),
            ("tm_mday", fl_tm.tm_mday, host_tm.tm_mday),
            ("tm_mon", fl_tm.tm_mon, host_tm.tm_mon),
            ("tm_year", fl_tm.tm_year, host_tm.tm_year),
            ("tm_wday", fl_tm.tm_wday, host_tm.tm_wday),
            ("tm_yday", fl_tm.tm_yday, host_tm.tm_yday),
        ] {
            assert_eq!(a, b, "{}: {name} differs (fl {a} vs glibc {b})", case.label);
        }
        assert_eq!(
            fl_tm.tm_gmtoff, host_tm.tm_gmtoff,
            "{}: tm_gmtoff differs (fl {} vs glibc {})",
            case.label, fl_tm.tm_gmtoff, host_tm.tm_gmtoff
        );
    }
}

fn measure_case(host: StrptimeFn, case: &Case) {
    let input = case.input.as_ptr().cast::<c_char>();
    let fmt = case.format.as_ptr().cast::<c_char>();
    let mut fl_tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut host_tm: libc::tm = unsafe { std::mem::zeroed() };

    let mut fl = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let (null_a_elapsed, null_b_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(input, fmt, &mut fl_tm));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(input, fmt, &mut fl_tm));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_fl(input, fmt, &mut fl_tm));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(input, fmt, &mut fl_tm));
            (start.elapsed(), b)
        };
        let (fl_elapsed, glibc_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(input, fmt, &mut fl_tm));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_host(host, input, fmt, &mut host_tm));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_host(host, input, fmt, &mut host_tm));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(input, fmt, &mut fl_tm));
            (start.elapsed(), b)
        };

        if sample >= WARMUP {
            let scale = REPS as f64;
            fl.push(fl_elapsed.as_nanos() as f64 / scale);
            glibc.push(glibc_elapsed.as_nanos() as f64 / scale);
            null_a.push(null_a_elapsed.as_nanos() as f64 / scale);
            null_b.push(null_b_elapsed.as_nanos() as f64 / scale);
        }
    }

    let effect = fl
        .iter()
        .zip(&glibc)
        .map(|(f, h)| f / h)
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
        "STRPTIME case={} samples={} reps/arm={REPS} fl_median_ns={:.3} glibc_median_ns={:.3}",
        case.label,
        fl.len(),
        median(&fl),
        median(&glibc),
    );
    println!(
        "STRPTIME_CONTRACT case={} kind=null_fl_fl ratio_median={null_median:.6} \
         ratio_ci95=[{null_low:.6},{null_high:.6}] ratio_cv_pct={:.3} ratio_mad={:.6}",
        case.label,
        cv_pct(&null),
        median_absolute_deviation(&null, null_median),
    );
    println!(
        "STRPTIME_CONTRACT case={} kind=fl_glibc ratio_median={effect_median:.6} \
         ratio_ci95=[{effect_low:.6},{effect_high:.6}] ratio_cv_pct={:.3} ratio_mad={:.6} \
         null_half_width={null_half_width:.6} clears_2x_null={clears_null} \
         comparison={comparison}",
        case.label,
        cv_pct(&effect),
        median_absolute_deviation(&effect, effect_median),
    );
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    // ISA + host provenance. `cfg!` is a COMPILE-TIME fact about this binary, so it reports
    // what the build actually received: an env `RUSTFLAGS` from the build orchestrator
    // overrides `.cargo/config.toml`'s `[build] rustflags` silently, and this is the only way
    // to see that from the artifact. A row concluding "we are at the SIMD floor" is only
    // meaningful if built_avx2=true. `is_x86_feature_detected!` is the EXECUTING cpu.
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
    let host_guard = host_wide_guard();
    require_host_wide_quiet(&host_guard, "startup");
    let requested_case = std::env::args().nth(1);
    let selected_cases = CASES
        .iter()
        .filter(|case| {
            requested_case
                .as_deref()
                .is_none_or(|requested| requested == case.label)
        })
        .collect::<Vec<_>>();
    assert!(
        !selected_cases.is_empty(),
        "unknown case {:?}; expected one of {}",
        requested_case,
        CASES
            .iter()
            .map(|case| case.label)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen(libc.so.6) failed");
    let setlocale: unsafe extern "C" fn(i32, *const c_char) -> *mut c_char =
        unsafe { std::mem::transmute(libc::dlsym(handle, c"setlocale".as_ptr())) };
    unsafe {
        setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    let sym = unsafe { libc::dlsym(handle, c"strptime".as_ptr()) };
    assert!(!sym.is_null(), "dlsym(strptime) failed");
    let host: StrptimeFn = unsafe { std::mem::transmute(sym) };

    for case in &selected_cases {
        verify(host, case);
    }
    println!("verify: OK (end pointer and every parsed tm field match host glibc)");
    for case in selected_cases {
        let pre_measurement = format!("pre_measurement_{}", case.label);
        require_host_wide_quiet(&host_guard, &pre_measurement);
        measure_case(host, case);
        let post_measurement = format!("post_measurement_{}", case.label);
        require_host_wide_quiet(&host_guard, &post_measurement);
    }
}
