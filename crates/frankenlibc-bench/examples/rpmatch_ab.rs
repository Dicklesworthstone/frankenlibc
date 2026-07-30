//! Falsifiable mechanism test: FrankenLibC `rpmatch` versus live host glibc.
//!
//! SHARP MECHANISM. A FrankenLibC specialization advantage is predicted only
//! when:
//!   (a) the claimed semantic slice is closed and full-domain equivalence is
//!       proved,
//!   (b) glibc still dispatches a data-driven interpreter on every call after
//!       all legitimate caching/hoisting, and
//!   (c) the deployed FrankenLibC path is already a bounded, allocation-free
//!       decision procedure rather than a second general interpreter.
//!
//! `rpmatch` satisfies all three in the C locale. Live glibc 2.42 caches the
//! compiled `YESEXPR` and `NOEXPR` regex objects, but it still performs one
//! cached `regexec` for a yes response and two for a no or invalid response.
//! FrankenLibC classifies the first byte with one closed-domain match.
//!
//! PRE-REGISTERED PREDICTION. Every conformant case should be faster in
//! FrankenLibC, and glibc's no/invalid cases should be slower than its yes case
//! because they traverse the second cached regex. A valid corrected-gate row
//! whose effect CI is not wholly below 1.0, or failure of that absolute-time
//! shape, refutes this version of the mechanism.
//!
//! Contract:
//!   * host `rpmatch` is linked normally in the process base namespace;
//!   * FrankenLibC is loaded from an explicit shared-object path with `dlopen`;
//!   * the benchmark ELF and both serving objects self-report SHA-256;
//!   * the arms must resolve to distinct objects or the run aborts;
//!   * exhaustive C-locale leading-byte conformance precedes timing;
//!   * every case carries FL/FL and glibc/glibc A/A controls;
//!   * bootstrap-median CIs and the corrected median-bias/2x-null rule decide;
//!   * CV is telemetry only.

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use frankenlibc_bench::HostWideBenchmarkGuard;
use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUPS: usize = 4;
const REPS: usize = 2_000;
const BOOTSTRAP_RESAMPLES: usize = 4_096;
const NULL_BIAS_TOLERANCE: f64 = 0.02;

type RpmatchFn = unsafe extern "C" fn(*const c_char) -> c_int;

unsafe extern "C" {
    #[link_name = "rpmatch"]
    fn linked_host_rpmatch(response: *const c_char) -> c_int;
    #[link_name = "setlocale"]
    fn linked_host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}

struct Config {
    fl_so: PathBuf,
    verify_only: bool,
}

struct Case {
    label: &'static str,
    response: &'static [u8],
    note: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "yes",
        response: b"yes\0",
        note: "YESEXPR matches; one cached glibc regex execution",
    },
    Case {
        label: "no",
        response: b"no\0",
        note: "YESEXPR misses then NOEXPR matches; two cached regex executions",
    },
    Case {
        label: "invalid",
        response: b"maybe\0",
        note: "both locale response regexes execute and miss",
    },
    Case {
        label: "empty",
        response: b"\0",
        note: "empty response; both locale response regexes execute and miss",
    },
];

#[derive(Debug)]
struct ObjectIdentity {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct CaseResult {
    label: &'static str,
    note: &'static str,
    fl_median_ns: f64,
    glibc_median_ns: f64,
    effect_median: f64,
    effect_low: f64,
    effect_high: f64,
    effect_cv_pct: f64,
    effect_mad: f64,
    fl_null_median: f64,
    fl_null_low: f64,
    fl_null_high: f64,
    fl_null_cv_pct: f64,
    fl_null_mad: f64,
    fl_null_holds: bool,
    glibc_null_median: f64,
    glibc_null_low: f64,
    glibc_null_high: f64,
    glibc_null_cv_pct: f64,
    glibc_null_mad: f64,
    glibc_null_holds: bool,
    null_half_width: f64,
    clears_2x_null: bool,
    comparison: &'static str,
}

impl CaseResult {
    fn print(&self, host_path: &Path) {
        println!(
            "RPMATCH case={} symbol=rpmatch host={} threads_actually_used=1 \
             samples={} reps_per_arm={} fl_median_ns={:.3} glibc_median_ns={:.3} note={:?}",
            self.label,
            host_path.display(),
            SAMPLES - WARMUPS,
            REPS,
            self.fl_median_ns,
            self.glibc_median_ns,
            self.note,
        );
        println!(
            "RPMATCH_CONTRACT case={} symbol=rpmatch kind=null_fl_fl \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
             null_holds={}",
            self.label,
            self.fl_null_median,
            self.fl_null_low,
            self.fl_null_high,
            self.fl_null_cv_pct,
            self.fl_null_mad,
            self.fl_null_holds,
        );
        println!(
            "RPMATCH_CONTRACT case={} symbol=rpmatch kind=null_glibc_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
             null_holds={}",
            self.label,
            self.glibc_null_median,
            self.glibc_null_low,
            self.glibc_null_high,
            self.glibc_null_cv_pct,
            self.glibc_null_mad,
            self.glibc_null_holds,
        );
        println!(
            "RPMATCH_CONTRACT case={} symbol=rpmatch kind=fl_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_half_width={:.6} clears_2x_null={} \
             nulls_hold={} comparison={} cv_role=telemetry_only \
             gate=corrected_null_median_bias",
            self.label,
            self.effect_median,
            self.effect_low,
            self.effect_high,
            self.effect_cv_pct,
            self.effect_mad,
            self.null_half_width,
            self.clears_2x_null,
            self.fl_null_holds && self.glibc_null_holds,
            self.comparison,
        );
    }
}

fn parse_args() -> Config {
    let mut args = std::env::args_os().skip(1);
    let mut fl_so = None;
    let mut verify_only = false;
    while let Some(arg) = args.next() {
        if arg == "--fl-so" {
            fl_so = args.next().map(PathBuf::from);
        } else if arg == "--verify-only" {
            verify_only = true;
        } else {
            panic!(
                "unknown argument {:?}; usage: rpmatch_ab --fl-so PATH [--verify-only]",
                arg
            );
        }
    }
    Config {
        fl_so: fl_so.expect("missing --fl-so PATH"),
        verify_only,
    }
}

fn sha256_file(path: &Path) -> Result<ObjectIdentity, String> {
    let path = std::fs::canonicalize(path)
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("read identity object {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("write SHA-256 hex");
    }
    Ok(ObjectIdentity {
        path,
        bytes: bytes.len() as u64,
        sha256: digest,
    })
}

fn symbol_object(symbol: *const c_void) -> Result<ObjectIdentity, String> {
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    if unsafe { libc::dladdr(symbol, &mut info) } == 0 || info.dli_fname.is_null() {
        return Err("dladdr could not identify serving object".to_owned());
    }
    let path = unsafe { CStr::from_ptr(info.dli_fname) };
    sha256_file(Path::new(OsStr::from_bytes(path.to_bytes())))
}

fn print_identity(role: &str, identity: &ObjectIdentity) {
    println!(
        "{role}_OBJECT path={} bytes={} sha256={}",
        identity.path.display(),
        identity.bytes,
        identity.sha256,
    );
}

fn dl_error(context: &str) -> String {
    let pointer = unsafe { libc::dlerror() };
    if pointer.is_null() {
        format!("{context}: unknown dynamic-loader error")
    } else {
        format!(
            "{context}: {}",
            unsafe { CStr::from_ptr(pointer) }.to_string_lossy()
        )
    }
}

fn median(values: &[f64]) -> f64 {
    assert!(!values.is_empty(), "median needs at least one value");
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn cv_pct(values: &[f64]) -> f64 {
    let average = mean(values);
    let variance = values
        .iter()
        .map(|value| (value - average) * (value - average))
        .sum::<f64>()
        / values.len() as f64;
    100.0 * variance.sqrt() / average
}

fn median_absolute_deviation(values: &[f64], center: f64) -> f64 {
    median(
        &values
            .iter()
            .map(|value| (value - center).abs())
            .collect::<Vec<_>>(),
    )
}

fn bootstrap_median_ci95(values: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ values.len() as u64;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; values.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = values[(state as usize) % values.len()];
        }
        medians.push(median(&resample));
    }
    medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1_000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1_000).min(BOOTSTRAP_RESAMPLES - 1);
    (medians[low], medians[high])
}

#[inline(never)]
fn run_batch(function: RpmatchFn, response: *const c_char) -> i64 {
    let mut accumulator = 0i64;
    for _ in 0..REPS {
        let result = unsafe { function(black_box(response)) };
        accumulator = accumulator.wrapping_add(i64::from(result));
    }
    black_box(accumulator)
}

fn time_batch(function: RpmatchFn, response: *const c_char) -> f64 {
    let started = Instant::now();
    black_box(run_batch(function, response));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

fn verify_response(host: RpmatchFn, fl: RpmatchFn, bytes: &[u8], label: &str) {
    assert!(
        !bytes.contains(&0),
        "verify_response input must not contain NUL"
    );
    let mut response = Vec::with_capacity(bytes.len() + 1);
    response.extend_from_slice(bytes);
    response.push(0);
    let pointer = response.as_ptr().cast::<c_char>();
    let host_result = unsafe { host(pointer) };
    let fl_result = unsafe { fl(pointer) };
    assert_eq!(
        fl_result, host_result,
        "rpmatch conformance mismatch for {label}: bytes={bytes:?}, \
         FrankenLibC={fl_result}, glibc={host_result}"
    );
}

fn verify_conformance(host: RpmatchFn, fl: RpmatchFn) -> usize {
    let mut comparisons = 0usize;
    verify_response(host, fl, b"", "empty");
    comparisons += 1;

    for lead in 1u16..=255 {
        let lead = lead as u8;
        verify_response(host, fl, &[lead], "single leading byte");
        verify_response(
            host,
            fl,
            &[lead, b'Y', 0xff, b'n'],
            "leading byte with arbitrary non-NUL tail",
        );
        comparisons += 2;
    }

    for response in [
        b"yes".as_slice(),
        b"YES".as_slice(),
        b"no".as_slice(),
        b"NO".as_slice(),
        b"maybe".as_slice(),
        b" yes".as_slice(),
        b"\ty".as_slice(),
        b"\xc3\xa9".as_slice(),
    ] {
        verify_response(host, fl, response, "curated response");
        comparisons += 1;
    }
    comparisons
}

fn measure_case(host: RpmatchFn, fl: RpmatchFn, case: &Case) -> CaseResult {
    let response = case.response.as_ptr().cast::<c_char>();
    let mut fl_effect = Vec::with_capacity(SAMPLES - WARMUPS);
    let mut glibc_effect = Vec::with_capacity(SAMPLES - WARMUPS);
    let mut fl_null_a = Vec::with_capacity(SAMPLES - WARMUPS);
    let mut fl_null_b = Vec::with_capacity(SAMPLES - WARMUPS);
    let mut glibc_null_a = Vec::with_capacity(SAMPLES - WARMUPS);
    let mut glibc_null_b = Vec::with_capacity(SAMPLES - WARMUPS);

    for sample in 0..SAMPLES {
        let mut fa = 0.0;
        let mut fb = 0.0;
        let mut ga = 0.0;
        let mut gb = 0.0;
        let mut effect_fl = 0.0;
        let mut effect_glibc = 0.0;

        // Rotate the three pair kinds so the effect is not always measured after
        // both nulls. Alternate arm order inside the effect pair by sample.
        for slot in 0..3 {
            match (sample + slot) % 3 {
                0 => {
                    fa = time_batch(fl, response);
                    fb = time_batch(fl, response);
                }
                1 => {
                    ga = time_batch(host, response);
                    gb = time_batch(host, response);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_batch(fl, response);
                    effect_glibc = time_batch(host, response);
                }
                2 => {
                    effect_glibc = time_batch(host, response);
                    effect_fl = time_batch(fl, response);
                }
                _ => unreachable!(),
            }
        }

        if sample >= WARMUPS {
            fl_effect.push(effect_fl);
            glibc_effect.push(effect_glibc);
            fl_null_a.push(fa);
            fl_null_b.push(fb);
            glibc_null_a.push(ga);
            glibc_null_b.push(gb);
        }
    }

    let effect = fl_effect
        .iter()
        .zip(&glibc_effect)
        .map(|(fl_time, glibc_time)| fl_time / glibc_time)
        .collect::<Vec<_>>();
    let fl_null = fl_null_b
        .iter()
        .zip(&fl_null_a)
        .map(|(second, first)| second / first)
        .collect::<Vec<_>>();
    let glibc_null = glibc_null_b
        .iter()
        .zip(&glibc_null_a)
        .map(|(second, first)| second / first)
        .collect::<Vec<_>>();

    let effect_median = median(&effect);
    let (effect_low, effect_high) = bootstrap_median_ci95(&effect);
    let fl_null_median = median(&fl_null);
    let (fl_null_low, fl_null_high) = bootstrap_median_ci95(&fl_null);
    let glibc_null_median = median(&glibc_null);
    let (glibc_null_low, glibc_null_high) = bootstrap_median_ci95(&glibc_null);
    let fl_half_width = (fl_null_low - 1.0).abs().max((fl_null_high - 1.0).abs());
    let glibc_half_width = (glibc_null_low - 1.0)
        .abs()
        .max((glibc_null_high - 1.0).abs());
    let null_half_width = fl_half_width.max(glibc_half_width);
    let fl_null_holds = (fl_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let glibc_null_holds = (glibc_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let clears_2x_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let effect_excludes_one = effect_high < 1.0 || effect_low > 1.0;
    let comparison = if !(fl_null_holds && glibc_null_holds) {
        "NULL_VIOLATED"
    } else if clears_2x_null && effect_excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if clears_2x_null && effect_excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    CaseResult {
        label: case.label,
        note: case.note,
        fl_median_ns: median(&fl_effect),
        glibc_median_ns: median(&glibc_effect),
        effect_median,
        effect_low,
        effect_high,
        effect_cv_pct: cv_pct(&effect),
        effect_mad: median_absolute_deviation(&effect, effect_median),
        fl_null_median,
        fl_null_low,
        fl_null_high,
        fl_null_cv_pct: cv_pct(&fl_null),
        fl_null_mad: median_absolute_deviation(&fl_null, fl_null_median),
        fl_null_holds,
        glibc_null_median,
        glibc_null_low,
        glibc_null_high,
        glibc_null_cv_pct: cv_pct(&glibc_null),
        glibc_null_mad: median_absolute_deviation(&glibc_null, glibc_null_median),
        glibc_null_holds,
        null_half_width,
        clears_2x_null,
        comparison,
    }
}

fn find_result<'a>(results: &'a [CaseResult], label: &str) -> &'a CaseResult {
    results
        .iter()
        .find(|result| result.label == label)
        .unwrap_or_else(|| panic!("missing result for {label}"))
}

fn prediction_verdict(results: &[CaseResult]) -> (&'static str, bool, bool) {
    let all_gates_valid = results.iter().all(|result| {
        result.fl_null_holds
            && result.glibc_null_holds
            && result.clears_2x_null
            && (result.effect_high < 1.0 || result.effect_low > 1.0)
    });
    if !all_gates_valid {
        return ("INCOMPLETE", false, false);
    }

    let every_case_faster = results
        .iter()
        .all(|result| result.comparison == "FL_FASTER" && result.effect_high < 1.0);
    let yes = find_result(results, "yes");
    let no = find_result(results, "no");
    let invalid = find_result(results, "invalid");
    let second_regex_shape =
        no.glibc_median_ns > yes.glibc_median_ns && invalid.glibc_median_ns > yes.glibc_median_ns;
    let verdict = if every_case_faster && second_regex_shape {
        "CONFIRMED"
    } else {
        "REFUTED"
    };
    (verdict, every_case_faster, second_regex_shape)
}

fn main() {
    let config = parse_args();
    let benchmark_identity =
        sha256_file(&std::env::current_exe().expect("resolve benchmark executable"))
            .expect("hash benchmark executable");
    print_identity("BENCH_ELF", &benchmark_identity);

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
        "HOST_IDENTITY hostname={} loadavg={} threads_actually_used=1",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned()),
        std::fs::read_to_string("/proc/loadavg")
            .map(|value| value
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(","))
            .unwrap_or_else(|_| "unknown".to_owned()),
    );

    let host_locale = unsafe { linked_host_setlocale(libc::LC_ALL, c"C".as_ptr()) };
    assert!(!host_locale.is_null(), "host setlocale(LC_ALL, C) failed");

    let supplied_fl_identity = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path = CString::new(supplied_fl_identity.path.as_os_str().as_bytes())
        .expect("FrankenLibC SO path contains NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_symbol = unsafe { libc::dlsym(handle, c"rpmatch".as_ptr()) };
    assert!(!fl_symbol.is_null(), "{}", dl_error("dlsym rpmatch"));

    let host: RpmatchFn = linked_host_rpmatch;
    let fl: RpmatchFn = unsafe { std::mem::transmute(fl_symbol) };
    let host_identity = symbol_object(host as *const () as *const c_void)
        .expect("identify directly linked host rpmatch object");
    let fl_identity =
        symbol_object(fl_symbol.cast_const()).expect("identify loaded FrankenLibC rpmatch object");
    print_identity("INCUMBENT", &host_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=rpmatch");
    println!("FL_LINKAGE explicit_dlopen_local symbol=rpmatch");

    assert!(
        host_identity
            .path
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b"libc.so")),
        "incumbent rpmatch resolved to {}, not host libc",
        host_identity.path.display()
    );
    assert_eq!(
        fl_identity.sha256, supplied_fl_identity.sha256,
        "loaded FrankenLibC object hash differs from supplied --fl-so object"
    );
    assert_ne!(
        host_identity.sha256, fl_identity.sha256,
        "both arms resolve to byte-identical objects"
    );
    assert_ne!(
        host as usize, fl as usize,
        "both arms resolve to the same function address"
    );

    let conformance_cases = verify_conformance(host, fl);
    println!(
        "RPMATCH_CONFORMANCE symbol=rpmatch locale=C leading_byte_domain=0..255 \
         arbitrary_tail_cases=255 comparisons={conformance_cases} verdict=pass"
    );
    if config.verify_only {
        println!("RPMATCH_VERIFY_ONLY verdict=pass");
        // Keep the comparison object resident until process exit.  FrankenLibC
        // owns process-global/TLS state; unloading it after calling an exported
        // symbol is not part of the supported libc lifecycle.
        return;
    }

    let guard = HostWideBenchmarkGuard::new().unwrap_or_else(|error| {
        eprintln!("RPMATCH_BLOCKED phase=guard_init error={error}");
        std::process::exit(2);
    });
    let pre = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("RPMATCH_BLOCKED phase=pre_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", pre.contract_line("pre_measurement"));

    let results = CASES
        .iter()
        .map(|case| measure_case(host, fl, case))
        .collect::<Vec<_>>();

    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("RPMATCH_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));

    for result in &results {
        result.print(&host_identity.path);
    }
    let (verdict, every_case_faster, second_regex_shape) = prediction_verdict(&results);
    let yes = find_result(&results, "yes");
    let no = find_result(&results, "no");
    let invalid = find_result(&results, "invalid");
    println!(
        "RPMATCH_PREDICTION verdict={verdict} every_case_faster={every_case_faster} \
         second_regex_shape={second_regex_shape} glibc_yes_ns={:.3} \
         glibc_no_ns={:.3} glibc_invalid_ns={:.3}",
        yes.glibc_median_ns, no.glibc_median_ns, invalid.glibc_median_ns,
    );

    // Keep the comparison object resident until process exit; see the
    // verify-only path above.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}
