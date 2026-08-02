//! Contract rerun for the historical `strftime` general-loop fixed floor.
//!
//! Each format is measured with a source-identical FL/FL null pair and an
//! FL/glibc effect pair in the same invocation. Pair order alternates by sample.
//! Bootstrap median CIs and the 2x null-half-width rule decide the comparison;
//! CV is descriptive only.

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

type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;

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
    format: &'static [u8],
}

const CASES: &[Case] = &[
    Case {
        label: "literal_short",
        format: b"just text no directives\0",
    },
    Case {
        label: "hm_exact",
        format: b"%H:%M\0",
    },
    // Bare `%H:%M:%S` — the most common timestamp format there is, and the exact
    // surface REJECTED at docs/NEGATIVE_EVIDENCE.md:7465 (2026-06-26) on a Criterion
    // abi-bench gate reading 1.33-1.38x LOSS, while that row's own direct release
    // examples read 0.178-0.221x WIN. The Criterion arm predates the quantified
    // abi-bench interposition hazard (referencing frankenlibc_abi::* links our
    // no_mangle allocator and interposes malloc process-wide), and the tell is in its
    // numbers: between harnesses the fl arm inflated ~3x while the glibc arm got
    // FASTER. `format_strftime_hms` is in core today; this case measures whether the
    // deployed ABI path actually reaches it.
    Case {
        label: "hms_exact",
        format: b"%H:%M:%S\0",
    },
    Case {
        label: "hms_12_exact",
        format: b"%I:%M:%S %p\0",
    },
    Case {
        label: "literal_long",
        format: b"a longer literal string of text with no percent directives at all here\0",
    },
    Case {
        label: "numeric_19",
        format: b"%Y-%m-%d %H:%M:%S\0",
    },
    Case {
        label: "mixed_general",
        format: b"prefix %A suffix\0",
    },
    Case {
        label: "mixed_month_general",
        format: b"prefix %B suffix\0",
    },
    Case {
        label: "weekday_abbrev",
        format: b"%a\0",
    },
    Case {
        label: "weekday_full",
        format: b"%A\0",
    },
    Case {
        label: "month_abbrev",
        format: b"%b\0",
    },
    Case {
        label: "month_full",
        format: b"%B\0",
    },
    Case {
        label: "month_alias_h",
        format: b"%h\0",
    },
    // Real-world shapes. The exact-leaf family already beats glibc (0.448-0.675) while
    // `mixed_general` — one directive wrapped in literal text — loses 11.7x on a 227 ns
    // frame. These probe where the boundary actually falls for formats people write:
    // aliases, all-directive runs with no literal, and the two most common
    // literal-interleaved timestamps in production code.
    Case {
        label: "alias_F",
        format: b"%F\0",
    },
    Case {
        label: "alias_D",
        format: b"%D\0",
    },
    Case {
        label: "alias_x",
        format: b"%x\0",
    },
    Case {
        label: "date_iso",
        format: b"%Y-%m-%d\0",
    },
    Case {
        label: "alias_T",
        format: b"%T\0",
    },
    Case {
        label: "alias_X",
        format: b"%X\0",
    },
    Case {
        label: "alias_R",
        format: b"%R\0",
    },
    Case {
        label: "alias_r",
        format: b"%r\0",
    },
    Case {
        label: "date_slash_dmy",
        format: b"%d/%m/%Y\0",
    },
    Case {
        label: "date_slash_mdy",
        format: b"%m/%d/%Y\0",
    },
    Case {
        label: "date_slash_mdy_short",
        format: b"%m/%d/%y\0",
    },
    Case {
        label: "compact_14",
        format: b"%Y%m%d%H%M%S\0",
    },
    // syslog RFC 3164 timestamp
    Case {
        label: "syslog_ts",
        format: b"%b %e %H:%M:%S\0",
    },
    // HTTP-date, RFC 7231 section 7.1.1.1 — emitted on essentially every response
    Case {
        label: "http_date",
        format: b"%a, %d %b %Y %H:%M:%S GMT\0",
    },
    // Canonical C-locale date/time representation. glibc resolves the locale's
    // D_T_FMT and interprets its nested format on every call; this is the
    // closed-language target for a straight-line FrankenLibC transducer.
    Case {
        label: "locale_datetime",
        format: b"%c\0",
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
    let variance = xs
        .iter()
        .map(|value| (value - avg) * (value - avg))
        .sum::<f64>()
        / xs.len() as f64;
    100.0 * variance.sqrt() / avg
}

fn median_absolute_deviation(xs: &[f64], center: f64) -> f64 {
    median(
        &xs.iter()
            .map(|value| (value - center).abs())
            .collect::<Vec<_>>(),
    )
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
fn run_fl(out: *mut c_char, fmt: *const c_char, tm: *const libc::tm, repetitions: usize) -> usize {
    let mut total = 0usize;
    for _ in 0..repetitions {
        total = total.wrapping_add(black_box(unsafe {
            frankenlibc_abi::time_abi::strftime(black_box(out), 128, black_box(fmt), black_box(tm))
        }));
    }
    black_box(total)
}

#[inline(never)]
fn run_host(
    host: StrftimeFn,
    out: *mut c_char,
    fmt: *const c_char,
    tm: *const libc::tm,
    repetitions: usize,
) -> usize {
    let mut total = 0usize;
    for _ in 0..repetitions {
        total = total.wrapping_add(black_box(unsafe {
            host(black_box(out), 128, black_box(fmt), black_box(tm))
        }));
    }
    black_box(total)
}

fn tm_observable_fields(tm: &libc::tm) -> (i32, i32, i32, i32, i32, i32, i32, i32, i32, i64) {
    (
        tm.tm_sec,
        tm.tm_min,
        tm.tm_hour,
        tm.tm_mday,
        tm.tm_mon,
        tm.tm_year,
        tm.tm_wday,
        tm.tm_yday,
        tm.tm_isdst,
        tm.tm_gmtoff,
    )
}

fn verify_one(host: StrftimeFn, case: &Case, tm: &libc::tm) {
    let fmt = case.format.as_ptr().cast();
    let expected_tm = tm_observable_fields(tm);
    for capacity in 1usize..=128 {
        assert_eq!(
            tm_observable_fields(tm),
            expected_tm,
            "{} shared fixture changed before capacity {capacity}",
            case.label,
        );
        let mut fl = [0x55 as c_char; 128];
        let mut glibc = [0x55 as c_char; 128];
        let fl_tm = *tm;
        let glibc_tm = *tm;
        assert_eq!(
            tm_observable_fields(tm),
            expected_tm,
            "{} shared fixture changed while copying capacity {capacity}",
            case.label,
        );
        let fl_n =
            unsafe { frankenlibc_abi::time_abi::strftime(fl.as_mut_ptr(), capacity, fmt, &fl_tm) };
        assert_eq!(
            tm_observable_fields(&fl_tm),
            expected_tm,
            "{} FrankenLibC arm mutated its const tm at capacity {capacity}",
            case.label,
        );
        assert_eq!(
            tm_observable_fields(tm),
            expected_tm,
            "{} FrankenLibC arm corrupted shared fixture at capacity {capacity}",
            case.label,
        );
        let glibc_n = unsafe { host(glibc.as_mut_ptr(), capacity, fmt, &glibc_tm) };
        assert_eq!(
            tm_observable_fields(&glibc_tm),
            expected_tm,
            "{} glibc arm mutated its const tm at capacity {capacity}",
            case.label,
        );
        assert_eq!(
            tm_observable_fields(tm),
            expected_tm,
            "{} glibc arm corrupted shared fixture at capacity {capacity}",
            case.label,
        );
        assert_eq!(
            fl_n, glibc_n,
            "{} length mismatch at capacity {capacity}; tm_mon={} tm_mday={} tm_hour={} tm_min={} tm_sec={}",
            case.label, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
        );
        if fl_n != 0 {
            assert_eq!(
                &fl[..=fl_n],
                &glibc[..=glibc_n],
                "{} output mismatch at capacity {capacity}",
                case.label
            );
        }
    }
}

fn verify(host: StrftimeFn, case: &Case, tm: &libc::tm) {
    verify_one(host, case, tm);
    if matches!(case.label, "hm_exact" | "alias_R") {
        for hour in [0, 23] {
            for minute in [0, 59] {
                let mut probe = *tm;
                probe.tm_hour = hour;
                probe.tm_min = minute;
                verify_one(host, case, &probe);
            }
        }
    }

    if matches!(
        case.label,
        "hms_exact" | "hms_12_exact" | "alias_T" | "alias_X" | "alias_r"
    ) {
        for hour in [0, 11, 12, 23] {
            for minute in [0, 59] {
                for second in [0, 59, 60] {
                    let mut probe = *tm;
                    probe.tm_hour = hour;
                    probe.tm_min = minute;
                    probe.tm_sec = second;
                    verify_one(host, case, &probe);
                }
            }
        }
    }

    if case.label == "mixed_general" {
        for weekday in 0..=6 {
            let mut probe = *tm;
            probe.tm_wday = weekday;
            verify_one(host, case, &probe);
        }
    }

    if case.label == "mixed_month_general" {
        for month in 0..=11 {
            let mut probe = *tm;
            probe.tm_mon = month;
            verify_one(host, case, &probe);
        }
    }

    if matches!(case.label, "weekday_abbrev" | "weekday_full") {
        for weekday in 0..=6 {
            let mut probe = *tm;
            probe.tm_wday = weekday;
            verify_one(host, case, &probe);
        }
    }

    if matches!(case.label, "month_abbrev" | "month_full" | "month_alias_h") {
        for month in 0..=11 {
            let mut probe = *tm;
            probe.tm_mon = month;
            verify_one(host, case, &probe);
        }
    }

    if matches!(case.label, "numeric_19" | "compact_14") {
        for year in [1000, 9999] {
            for month in 0..=11 {
                for day in [1, 9, 10, 31] {
                    for hour in [0, 23] {
                        for minute in [0, 59] {
                            for second in [0, 59, 60] {
                                let mut probe = *tm;
                                probe.tm_year = year - 1900;
                                probe.tm_mon = month;
                                probe.tm_mday = day;
                                probe.tm_hour = hour;
                                probe.tm_min = minute;
                                probe.tm_sec = second;
                                verify_one(host, case, &probe);
                            }
                        }
                    }
                }
            }
        }
    }

    if matches!(
        case.label,
        "alias_D"
            | "alias_F"
            | "alias_x"
            | "date_iso"
            | "date_slash_dmy"
            | "date_slash_mdy"
            | "date_slash_mdy_short"
    ) {
        for year in [1000, 9999] {
            for month in 0..=11 {
                for day in [1, 9, 10, 31] {
                    let mut probe = *tm;
                    probe.tm_year = year - 1900;
                    probe.tm_mon = month;
                    probe.tm_mday = day;
                    verify_one(host, case, &probe);
                }
            }
        }
    }

    if case.label == "syslog_ts" {
        for month in 0..=11 {
            for day in [1, 9, 10, 31] {
                for hour in [0, 23] {
                    for minute in [0, 59] {
                        for second in [0, 59, 60] {
                            let mut probe = *tm;
                            probe.tm_mon = month;
                            probe.tm_mday = day;
                            probe.tm_hour = hour;
                            probe.tm_min = minute;
                            probe.tm_sec = second;
                            verify_one(host, case, &probe);
                        }
                    }
                }
            }
        }
    }

    if case.label == "http_date" {
        for weekday in 0..=6 {
            for month in 0..=11 {
                for day in [1, 9, 10, 31] {
                    for year in [1000, 9999] {
                        for hour in [0, 23] {
                            for minute in [0, 59] {
                                for second in [0, 59, 60] {
                                    let mut probe = *tm;
                                    probe.tm_wday = weekday;
                                    probe.tm_mon = month;
                                    probe.tm_mday = day;
                                    probe.tm_year = year - 1900;
                                    probe.tm_hour = hour;
                                    probe.tm_min = minute;
                                    probe.tm_sec = second;
                                    verify_one(host, case, &probe);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if case.label == "locale_datetime" {
        for weekday in 0..=6 {
            for month in 0..=11 {
                for day in [1, 9, 10, 31] {
                    for year in [1000, 9999] {
                        for hour in [0, 23] {
                            for minute in [0, 59] {
                                for second in [0, 59, 60] {
                                    let mut probe = *tm;
                                    probe.tm_wday = weekday;
                                    probe.tm_mon = month;
                                    probe.tm_mday = day;
                                    probe.tm_year = year - 1900;
                                    probe.tm_hour = hour;
                                    probe.tm_min = minute;
                                    probe.tm_sec = second;
                                    verify_one(host, case, &probe);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // POSIX leaves the stored characters unspecified when a conversion's
    // referenced `tm` field is outside its normal range. The core unit test
    // proves those inputs decline this finite leaf; they are deliberately not
    // differential claims against one particular glibc behavior.
}

fn measure_case(host: StrftimeFn, case: &Case, tm: &libc::tm, repetitions: usize) {
    let fmt = case.format.as_ptr().cast();
    let mut fl_out = [0 as c_char; 128];
    let mut host_out = [0 as c_char; 128];
    let fl_tm = *tm;
    let host_tm = *tm;
    let expected_tm = tm_observable_fields(tm);
    let mut fl = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let (null_a_elapsed, null_b_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt, &fl_tm, repetitions));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt, &fl_tm, repetitions));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt, &fl_tm, repetitions));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt, &fl_tm, repetitions));
            (start.elapsed(), b)
        };
        let (fl_elapsed, glibc_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt, &fl_tm, repetitions));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_host(
                host,
                host_out.as_mut_ptr(),
                fmt,
                &host_tm,
                repetitions,
            ));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_host(
                host,
                host_out.as_mut_ptr(),
                fmt,
                &host_tm,
                repetitions,
            ));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt, &fl_tm, repetitions));
            (start.elapsed(), b)
        };

        if sample >= WARMUP {
            let scale = repetitions as f64;
            fl.push(fl_elapsed.as_nanos() as f64 / scale);
            glibc.push(glibc_elapsed.as_nanos() as f64 / scale);
            null_a.push(null_a_elapsed.as_nanos() as f64 / scale);
            null_b.push(null_b_elapsed.as_nanos() as f64 / scale);
        }
    }
    assert_eq!(
        tm_observable_fields(&fl_tm),
        expected_tm,
        "{} FrankenLibC timing arm mutated its const tm",
        case.label,
    );
    assert_eq!(
        tm_observable_fields(&host_tm),
        expected_tm,
        "{} glibc timing arm mutated its const tm",
        case.label,
    );

    let effect = fl
        .iter()
        .zip(&glibc)
        .map(|(fl_ns, host_ns)| fl_ns / host_ns)
        .collect::<Vec<_>>();
    let null = null_b
        .iter()
        .zip(&null_a)
        .map(|(b_ns, a_ns)| b_ns / a_ns)
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
        "STRFTIME_FIXED_FLOOR case={} samples={} reps/arm={repetitions} fl_median_ns={:.3} \
         glibc_median_ns={:.3}",
        case.label,
        fl.len(),
        median(&fl),
        median(&glibc),
    );
    println!(
        "STRFTIME_FIXED_FLOOR_CONTRACT case={} kind=null_fl_fl \
         ratio_median={null_median:.6} ratio_ci95=[{null_low:.6},{null_high:.6}] \
         ratio_cv_pct={:.3} ratio_mad={:.6}",
        case.label,
        cv_pct(&null),
        median_absolute_deviation(&null, null_median),
    );
    println!(
        "STRFTIME_FIXED_FLOOR_CONTRACT case={} kind=fl_glibc \
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
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null());
    let setlocale: unsafe extern "C" fn(i32, *const c_char) -> *mut c_char =
        unsafe { std::mem::transmute(libc::dlsym(handle, c"setlocale".as_ptr())) };
    unsafe {
        setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    let host: StrftimeFn =
        unsafe { std::mem::transmute(libc::dlsym(handle, c"strftime".as_ptr())) };

    let mut selected_case = None;
    let mut repetition_counts = vec![REPS];
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--case" => {
                selected_case = Some(args.next().expect("--case requires a label"));
            }
            "--reps" => {
                let values = args
                    .next()
                    .expect("--reps requires one or more comma-separated positive integers");
                repetition_counts = values
                    .split(',')
                    .map(|value| {
                        let parsed = value
                            .parse()
                            .expect("--reps values must be positive integers");
                        assert!(parsed > 0, "--reps values must be positive");
                        parsed
                    })
                    .collect();
            }
            _ => panic!("unknown argument: {arg}"),
        }
    }
    let cases = CASES
        .iter()
        .filter(|case| {
            selected_case
                .as_deref()
                .is_none_or(|label| case.label == label)
        })
        .collect::<Vec<_>>();
    assert!(
        !cases.is_empty(),
        "no benchmark case matched {:?}",
        selected_case
    );

    // Fixed 2023-11-14 22:13:20 UTC fixture. Construct it directly so this
    // strftime harness does not route fixture setup through either gmtime arm.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = 20;
    tm.tm_min = 13;
    tm.tm_hour = 22;
    tm.tm_mday = 14;
    tm.tm_mon = 10;
    tm.tm_year = 123;
    tm.tm_wday = 2;
    tm.tm_yday = 317;
    tm.tm_isdst = 0;
    tm.tm_gmtoff = 0;
    tm.tm_zone = c"UTC".as_ptr();
    for case in &cases {
        verify(host, case, &tm);
    }
    println!(
        "verify: OK ({} case(s) and capacities 1..=128 match host glibc)",
        cases.len()
    );
    for repetitions in repetition_counts {
        for case in &cases {
            let pre_measurement = format!("pre_measurement_{}_{}", case.label, repetitions);
            require_host_wide_quiet(&host_guard, &pre_measurement);
            measure_case(host, case, &tm, repetitions);
            let post_measurement = format!("post_measurement_{}_{}", case.label, repetitions);
            require_host_wide_quiet(&host_guard, &post_measurement);
        }
    }
}
