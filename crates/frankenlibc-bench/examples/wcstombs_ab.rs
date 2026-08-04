//! Live-incumbent conversion for the held `wcsrtombs` count-mode SIMD claim.
//!
//! The original count benchmark called FrankenLibC directly but put glibc in a
//! fresh `dlmopen` namespace. Locale-sensitive conversion in a fresh namespace
//! is known to produce impossible glibc timings, so those ratios are not
//! competitive evidence. This replacement links host glibc normally, loads the
//! deployed FrankenLibC object explicitly, proves observable conversion parity
//! before timing, and applies the corrected paired-median null gate. Because
//! FrankenLibC supports only the C/POSIX locale, only the historical ASCII cell
//! has a common locale contract. The three multibyte cells are checked and
//! reported as incomparable instead of timing C against C.UTF-8.
//!
//! Run from a clean committed base plus this one reserved overlay:
//! `RCH_REQUIRE_REMOTE=1 RCH_WORKER=<worker> \
//!  rch exec --base <commit> --clean-overlay \
//!  --overlay-path crates/frankenlibc-bench/examples/wcstombs_ab.rs -- \
//!  env -u CARGO_TARGET_DIR \
//!  FRANKENLIBC_BENCH_TARGET_DIR=/data/tmp/cargo-target-frankenlibc \
//!  cargo --config 'build.target-dir="/data/tmp/cargo-target-frankenlibc"' \
//!  run -j2 --profile release -p frankenlibc-bench --features abi-bench \
//!  --example wcstombs_ab`

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use frankenlibc_bench::HostWideBenchmarkGuard;
use sha2::{Digest, Sha256};

const SAMPLES: usize = 40;
const WARMUPS: usize = 4;
const BOOTSTRAP_RESAMPLES: usize = 4_096;
const NULL_BIAS_TOLERANCE: f64 = 0.02;
const CODEPOINTS_PER_TIMED_ARM: usize = 20_000_000;
const MIN_REPS: usize = 2_000;
const OUTPUT_SENTINEL: u8 = 0xa5;

type WcsrtombsFn = unsafe extern "C" fn(
    *mut c_char,
    *mut *const libc::wchar_t,
    usize,
    *mut libc::mbstate_t,
) -> usize;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;
type MbsinitFn = unsafe extern "C" fn(*const libc::mbstate_t) -> c_int;

unsafe extern "C" {
    #[link_name = "wcsrtombs"]
    fn linked_host_wcsrtombs(
        destination: *mut c_char,
        source: *mut *const libc::wchar_t,
        length: usize,
        state: *mut libc::mbstate_t,
    ) -> usize;
    #[link_name = "setlocale"]
    fn linked_host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    #[link_name = "__errno_location"]
    fn linked_host_errno_location() -> *mut c_int;
    #[link_name = "mbsinit"]
    fn linked_host_mbsinit(state: *const libc::mbstate_t) -> c_int;
}

struct Config {
    fl_so: PathBuf,
    target_dir: PathBuf,
    verify_only: bool,
    build_fl_if_missing: bool,
}

struct Case {
    label: &'static str,
    wide: Vec<libc::wchar_t>,
    note: &'static str,
}

impl Case {
    fn codepoints(&self) -> usize {
        self.wide.len() - 1
    }

    fn reps(&self) -> usize {
        (CODEPOINTS_PER_TIMED_ARM / self.codepoints().max(1)).max(MIN_REPS)
    }
}

#[derive(Debug)]
struct ObjectIdentity {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Observation {
    result: usize,
    source_offset: Option<usize>,
    output: Vec<u8>,
    errno: c_int,
    state_is_initial: bool,
}

#[derive(Debug)]
struct CaseResult {
    label: &'static str,
    note: &'static str,
    codepoints: usize,
    reps: usize,
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
    fn decidable(&self) -> bool {
        matches!(self.comparison, "FL_FASTER" | "FL_SLOWER")
    }

    fn print(&self, host_path: &Path, threads_pre: usize, threads_post: usize) {
        println!(
            "WCSRTOMBS_COUNT symbol=wcsrtombs case={} locale=C host={} \
             codepoints={} threads_observed_pre={threads_pre} \
             threads_observed_post={threads_post} samples={} reps_per_arm={} \
             fl_median_ns={:.3} glibc_median_ns={:.3} note={:?}",
            self.label,
            host_path.display(),
            self.codepoints,
            SAMPLES - WARMUPS,
            self.reps,
            self.fl_median_ns,
            self.glibc_median_ns,
            self.note,
        );
        println!(
            "WCSRTOMBS_COUNT_CONTRACT symbol=wcsrtombs case={} kind=null_fl_fl \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
             null_median_within_tolerance={} null_ci_straddle_veto=false \
             cv_role=telemetry_only gate=corrected_null_median_bias",
            self.label,
            self.fl_null_median,
            self.fl_null_low,
            self.fl_null_high,
            self.fl_null_cv_pct,
            self.fl_null_mad,
            self.fl_null_holds,
        );
        println!(
            "WCSRTOMBS_COUNT_CONTRACT symbol=wcsrtombs case={} kind=null_glibc_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
             null_median_within_tolerance={} null_ci_straddle_veto=false \
             cv_role=telemetry_only gate=corrected_null_median_bias",
            self.label,
            self.glibc_null_median,
            self.glibc_null_low,
            self.glibc_null_high,
            self.glibc_null_cv_pct,
            self.glibc_null_mad,
            self.glibc_null_holds,
        );
        println!(
            "WCSRTOMBS_COUNT_CONTRACT symbol=wcsrtombs case={} kind=fl_glibc \
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
    while let Some(argument) = args.next() {
        if argument == "--fl-so" {
            fl_so = args.next().map(PathBuf::from);
        } else if argument == "--verify-only" {
            verify_only = true;
        } else {
            panic!(
                "unknown argument {argument:?}; usage: wcstombs_ab \
                 [--fl-so PATH] [--verify-only]"
            );
        }
    }

    let target_dir = std::env::var_os("FRANKENLIBC_BENCH_TARGET_DIR")
        .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    let build_fl_if_missing = fl_so.is_none();
    let fl_so = fl_so.unwrap_or_else(|| target_dir.join("release/libfrankenlibc_abi.so"));
    Config {
        fl_so,
        target_dir,
        verify_only,
        build_fl_if_missing,
    }
}

fn ensure_fl_shared_object(config: &Config) {
    if config.fl_so.is_file() {
        return;
    }
    assert!(
        config.build_fl_if_missing,
        "explicit FrankenLibC SO does not exist: {}",
        config.fl_so.display()
    );

    let cargo_query = Command::new("rustup")
        .args(["which", "cargo"])
        .output()
        .expect("run rustup which cargo");
    assert!(
        cargo_query.status.success(),
        "rustup could not resolve active Cargo: {}",
        String::from_utf8_lossy(&cargo_query.stderr)
    );
    let cargo = PathBuf::from(
        String::from_utf8(cargo_query.stdout)
            .expect("rustup cargo path is UTF-8")
            .trim(),
    );
    let build = Command::new(&cargo)
        .env("CARGO_TARGET_DIR", &config.target_dir)
        .args([
            "build",
            "--quiet",
            "-j2",
            "-p",
            "frankenlibc-abi",
            "--profile",
            "release",
        ])
        .output()
        .expect("build FrankenLibC ABI cdylib");
    assert!(
        build.status.success(),
        "FrankenLibC ABI cdylib build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr),
    );
    assert!(
        config.fl_so.is_file(),
        "Cargo build succeeded but did not produce {}",
        config.fl_so.display()
    );
    println!(
        "FL_BUILD source=clean_overlay_runtime_cargo builder={} target_dir={} artifact={}",
        cargo.display(),
        config.target_dir.display(),
        config.fl_so.display()
    );
}

fn sha256_file(path: &Path) -> Result<ObjectIdentity, String> {
    let path = std::fs::canonicalize(path)
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("read identity object {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut sha256 = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut sha256, "{byte:02x}").expect("write SHA-256 hex");
    }
    Ok(ObjectIdentity {
        path,
        bytes: bytes.len() as u64,
        sha256,
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

fn observed_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn make_wide(text: &str) -> Vec<libc::wchar_t> {
    text.chars()
        .map(|character| character as libc::wchar_t)
        .chain(std::iter::once(0))
        .collect()
}

fn timing_cases() -> Vec<Case> {
    vec![Case {
        label: "ascii",
        wide: make_wide(&"The quick brown fox jumps over the lazy dog. ".repeat(30)),
        note: "historical long all-ASCII count fixture under shared C locale",
    }]
}

fn incomparable_multibyte_cases() -> Vec<Case> {
    let cyrillic = (0..300)
        .map(|index| char::from_u32(0x0410 + (index % 0x40)).expect("valid Cyrillic scalar"))
        .collect::<String>();
    let cjk = (0..300)
        .map(|index| char::from_u32(0x4e00 + (index % 0x400)).expect("valid CJK scalar"))
        .collect::<String>();
    vec![
        Case {
            label: "mixed",
            wide: make_wide(&"café résumé naïve façade ".repeat(40)),
            note: "historical Latin mixed-width fixture requires UTF-8 locale",
        },
        Case {
            label: "cyrillic",
            wide: make_wide(&cyrillic),
            note: "historical Cyrillic fixture requires UTF-8 locale",
        },
        Case {
            label: "cjk",
            wide: make_wide(&cjk),
            note: "historical CJK fixture requires UTF-8 locale",
        },
    ]
}

fn source_offset(input: &[libc::wchar_t], source: *const libc::wchar_t) -> Option<usize> {
    if source.is_null() {
        return None;
    }
    let start = input.as_ptr() as usize;
    let address = source as usize;
    let byte_len = input.len() * std::mem::size_of::<libc::wchar_t>();
    assert!(
        (start..=start + byte_len).contains(&address),
        "wcsrtombs returned a source pointer outside the input"
    );
    let displacement = address - start;
    assert_eq!(
        displacement % std::mem::size_of::<libc::wchar_t>(),
        0,
        "wcsrtombs returned a misaligned source pointer"
    );
    Some(displacement / std::mem::size_of::<libc::wchar_t>())
}

fn observe(
    function: WcsrtombsFn,
    errno_location: ErrnoLocationFn,
    mbsinit: MbsinitFn,
    input: &[libc::wchar_t],
    output_capacity: Option<usize>,
    explicit_state: bool,
) -> Observation {
    let mut output = output_capacity
        .map(|capacity| vec![OUTPUT_SENTINEL; capacity])
        .unwrap_or_default();
    let destination = if output_capacity.is_some() {
        output.as_mut_ptr().cast::<c_char>()
    } else {
        std::ptr::null_mut()
    };
    let mut source = input.as_ptr();
    let mut state: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let state_pointer = if explicit_state {
        &mut state
    } else {
        std::ptr::null_mut()
    };
    unsafe { *errno_location() = libc::EBUSY };
    let result = unsafe {
        function(
            destination,
            &mut source,
            output_capacity.unwrap_or(0),
            state_pointer,
        )
    };
    Observation {
        result,
        source_offset: source_offset(input, source),
        output,
        errno: unsafe { *errno_location() },
        state_is_initial: unsafe { mbsinit(&state) != 0 },
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_observation(
    host: WcsrtombsFn,
    fl: WcsrtombsFn,
    host_errno: ErrnoLocationFn,
    fl_errno: ErrnoLocationFn,
    host_mbsinit: MbsinitFn,
    fl_mbsinit: MbsinitFn,
    input: &[libc::wchar_t],
    output_capacity: Option<usize>,
    explicit_state: bool,
    label: &str,
) -> Observation {
    let host_observation = observe(
        host,
        host_errno,
        host_mbsinit,
        input,
        output_capacity,
        explicit_state,
    );
    let fl_observation = observe(
        fl,
        fl_errno,
        fl_mbsinit,
        input,
        output_capacity,
        explicit_state,
    );
    assert_eq!(
        fl_observation, host_observation,
        "wcsrtombs conformance mismatch for {label}"
    );
    host_observation
}

#[allow(clippy::too_many_arguments)]
fn verify_success_case(
    host: WcsrtombsFn,
    fl: WcsrtombsFn,
    host_errno: ErrnoLocationFn,
    fl_errno: ErrnoLocationFn,
    host_mbsinit: MbsinitFn,
    fl_mbsinit: MbsinitFn,
    case: &Case,
) -> usize {
    let count = compare_observation(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &case.wide,
        None,
        true,
        &format!("{}/count_explicit_state", case.label),
    );
    assert_ne!(
        count.result,
        usize::MAX,
        "successful case {} was not representable",
        case.label
    );
    compare_observation(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &case.wide,
        None,
        false,
        &format!("{}/count_internal_state", case.label),
    );
    compare_observation(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &case.wide,
        Some(count.result + 1),
        true,
        &format!("{}/full_write", case.label),
    );
    compare_observation(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &case.wide,
        Some((count.result / 2).max(1)),
        true,
        &format!("{}/bounded_write", case.label),
    );
    count.result
}

#[allow(clippy::too_many_arguments)]
fn verify_conformance(
    host: WcsrtombsFn,
    fl: WcsrtombsFn,
    host_errno: ErrnoLocationFn,
    fl_errno: ErrnoLocationFn,
    host_mbsinit: MbsinitFn,
    fl_mbsinit: MbsinitFn,
    cases: &[Case],
) -> (Vec<usize>, usize) {
    let expected_counts = cases
        .iter()
        .map(|case| {
            verify_success_case(
                host,
                fl,
                host_errno,
                fl_errno,
                host_mbsinit,
                fl_mbsinit,
                case,
            )
        })
        .collect::<Vec<_>>();
    let mut comparisons = cases.len() * 4;

    let empty = Case {
        label: "empty",
        wide: vec![0],
        note: "empty edge case",
    };
    verify_success_case(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &empty,
    );
    comparisons += 4;

    let invalid = [0xd800 as libc::wchar_t, 0];
    for (label, output_capacity, explicit_state) in [
        ("invalid/count_explicit_state", None, true),
        ("invalid/count_internal_state", None, false),
        ("invalid/full_write", Some(16), true),
    ] {
        let observation = compare_observation(
            host,
            fl,
            host_errno,
            fl_errno,
            host_mbsinit,
            fl_mbsinit,
            &invalid,
            output_capacity,
            explicit_state,
            label,
        );
        assert_eq!(
            observation.result,
            usize::MAX,
            "invalid scalar must return (size_t)-1 for {label}"
        );
        comparisons += 1;
    }

    (expected_counts, comparisons)
}

#[allow(clippy::too_many_arguments)]
fn verify_incomparable_multibyte_cases(
    host: WcsrtombsFn,
    fl: WcsrtombsFn,
    host_errno: ErrnoLocationFn,
    fl_errno: ErrnoLocationFn,
    host_mbsinit: MbsinitFn,
    fl_mbsinit: MbsinitFn,
    cases: &[Case],
) -> usize {
    for case in cases {
        let host_observation = observe(host, host_errno, host_mbsinit, &case.wide, None, true);
        let fl_observation = observe(fl, fl_errno, fl_mbsinit, &case.wide, None, true);
        assert_eq!(
            host_observation.result,
            usize::MAX,
            "host C locale unexpectedly represented non-ASCII case {}",
            case.label
        );
        assert_ne!(
            fl_observation.result,
            usize::MAX,
            "FrankenLibC C locale unexpectedly rejected non-ASCII case {}",
            case.label
        );
        println!(
            "WCSRTOMBS_INCOMPARABLE symbol=wcsrtombs case={} \
             reason=no_common_utf8_locale host_locale=C host_result=size_t_max \
             host_errno={} fl_locale=C fl_result={} fl_errno={} note={:?}",
            case.label,
            host_observation.errno,
            fl_observation.result,
            fl_observation.errno,
            case.note,
        );
    }
    cases.len()
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
fn run_count_batch(function: WcsrtombsFn, input: &[libc::wchar_t], reps: usize) -> usize {
    let mut accumulator = 0usize;
    for _ in 0..reps {
        let mut source = black_box(input.as_ptr());
        let result = unsafe {
            function(
                std::ptr::null_mut(),
                black_box(&mut source),
                0,
                std::ptr::null_mut(),
            )
        };
        accumulator = accumulator.wrapping_add(black_box(result));
        black_box(source);
    }
    black_box(accumulator)
}

fn time_count_batch(function: WcsrtombsFn, case: &Case, expected: usize, reps: usize) -> f64 {
    let started = Instant::now();
    let total = run_count_batch(function, &case.wide, reps);
    let elapsed = started.elapsed().as_secs_f64() * 1_000_000_000.0 / reps as f64;
    assert_eq!(
        total,
        expected.wrapping_mul(reps),
        "wcsrtombs timed batch returned an error for {}",
        case.label,
    );
    elapsed
}

fn measure_case(host: WcsrtombsFn, fl: WcsrtombsFn, case: &Case, expected: usize) -> CaseResult {
    let reps = case.reps();
    let retained = SAMPLES - WARMUPS;
    let mut fl_effect = Vec::with_capacity(retained);
    let mut glibc_effect = Vec::with_capacity(retained);
    let mut fl_null_a = Vec::with_capacity(retained);
    let mut fl_null_b = Vec::with_capacity(retained);
    let mut glibc_null_a = Vec::with_capacity(retained);
    let mut glibc_null_b = Vec::with_capacity(retained);

    for sample in 0..SAMPLES {
        let mut effect_fl = 0.0;
        let mut effect_glibc = 0.0;
        let mut fa = 0.0;
        let mut fb = 0.0;
        let mut ga = 0.0;
        let mut gb = 0.0;

        for slot in 0..3 {
            match (sample + slot) % 3 {
                0 if sample % 2 == 0 => {
                    fa = time_count_batch(fl, case, expected, reps);
                    fb = time_count_batch(fl, case, expected, reps);
                }
                0 => {
                    fb = time_count_batch(fl, case, expected, reps);
                    fa = time_count_batch(fl, case, expected, reps);
                }
                1 if sample % 2 == 0 => {
                    ga = time_count_batch(host, case, expected, reps);
                    gb = time_count_batch(host, case, expected, reps);
                }
                1 => {
                    gb = time_count_batch(host, case, expected, reps);
                    ga = time_count_batch(host, case, expected, reps);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_count_batch(fl, case, expected, reps);
                    effect_glibc = time_count_batch(host, case, expected, reps);
                }
                2 => {
                    effect_glibc = time_count_batch(host, case, expected, reps);
                    effect_fl = time_count_batch(fl, case, expected, reps);
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
        .map(|(fl_ns, glibc_ns)| fl_ns / glibc_ns)
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
    let fl_null_holds = (fl_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let glibc_null_holds = (glibc_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let fl_half_width = (fl_null_low - 1.0).abs().max((fl_null_high - 1.0).abs());
    let glibc_half_width = (glibc_null_low - 1.0)
        .abs()
        .max((glibc_null_high - 1.0).abs());
    let null_half_width = fl_half_width.max(glibc_half_width);
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
        codepoints: case.codepoints(),
        reps,
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

fn main() {
    let config = parse_args();
    ensure_fl_shared_object(&config);

    let benchmark_identity =
        sha256_file(&std::env::current_exe().expect("resolve benchmark executable"))
            .expect("hash benchmark executable");
    print_identity("BENCH_ELF", &benchmark_identity);
    println!(
        "HOST_IDENTITY hostname={} loadavg={}",
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

    let host_locale = unsafe { linked_host_setlocale(libc::LC_ALL, c"C".as_ptr()) };
    assert!(!host_locale.is_null(), "host setlocale(LC_ALL, C) failed");

    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let resolve = |name: &CStr| {
        let symbol = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(
            !symbol.is_null(),
            "{}",
            dl_error(&format!("dlsym FrankenLibC {}", name.to_string_lossy()))
        );
        symbol
    };
    let fl_wcsrtombs_symbol = resolve(c"wcsrtombs");
    let fl_setlocale_symbol = resolve(c"setlocale");
    let fl_errno_symbol = resolve(c"__errno_location");
    let fl_mbsinit_symbol = resolve(c"mbsinit");
    let fl: WcsrtombsFn = unsafe { std::mem::transmute(fl_wcsrtombs_symbol) };
    let fl_setlocale: SetlocaleFn = unsafe { std::mem::transmute(fl_setlocale_symbol) };
    let fl_errno: ErrnoLocationFn = unsafe { std::mem::transmute(fl_errno_symbol) };
    let fl_mbsinit: MbsinitFn = unsafe { std::mem::transmute(fl_mbsinit_symbol) };
    assert!(
        !unsafe { fl_setlocale(libc::LC_ALL, c"C".as_ptr()) }.is_null(),
        "FrankenLibC setlocale(LC_ALL, C) failed"
    );

    let host: WcsrtombsFn = linked_host_wcsrtombs;
    let host_errno: ErrnoLocationFn = linked_host_errno_location;
    let host_mbsinit: MbsinitFn = linked_host_mbsinit;
    let incumbent_identity = symbol_object(host as *const () as *const c_void)
        .expect("identify directly linked host wcsrtombs object");
    let fl_identity = symbol_object(fl_wcsrtombs_symbol.cast_const())
        .expect("identify loaded FrankenLibC wcsrtombs object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=wcsrtombs");
    println!("FL_LINKAGE explicit_dlopen_local symbol=wcsrtombs");
    println!(
        "ARM_DISTINCT symbol=wcsrtombs incumbent_address={:#x} fl_address={:#x}",
        host as usize, fl as usize,
    );
    assert!(
        incumbent_identity
            .path
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b"libc.so")),
        "incumbent resolved to {}, not host libc",
        incumbent_identity.path.display()
    );
    assert_eq!(
        fl_identity.sha256, supplied_fl.sha256,
        "loaded FrankenLibC object differs from supplied object"
    );
    assert_ne!(
        incumbent_identity.sha256, fl_identity.sha256,
        "both arms resolve to byte-identical objects"
    );
    assert_ne!(
        host as usize, fl as usize,
        "both arms resolve to the same function address"
    );

    let threads_initial = observed_threads();
    assert_eq!(
        threads_initial, 1,
        "wcsrtombs harness requires one actually observed process thread"
    );
    let cases = timing_cases();
    let incomparable_cases = incomparable_multibyte_cases();
    let (expected_counts, conformance_comparisons) = verify_conformance(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &cases,
    );
    let incomparable = verify_incomparable_multibyte_cases(
        host,
        fl,
        host_errno,
        fl_errno,
        host_mbsinit,
        fl_mbsinit,
        &incomparable_cases,
    );
    println!(
        "WCSRTOMBS_CONFORMANCE symbol=wcsrtombs locale=C timing_cases={} \
         incomparable_multibyte_cases={incomparable} edge_cases=2 \
         comparable_observations={conformance_comparisons} \
         threads_observed={threads_initial} verdict=pass",
        cases.len(),
    );
    if config.verify_only {
        println!("WCSRTOMBS_VERIFY_ONLY symbol=wcsrtombs verdict=pass");
        return;
    }

    let guard = HostWideBenchmarkGuard::new().unwrap_or_else(|error| {
        eprintln!("WCSRTOMBS_BLOCKED phase=guard_init error={error}");
        std::process::exit(2);
    });
    let pre = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("WCSRTOMBS_BLOCKED phase=pre_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", pre.contract_line("pre_measurement"));
    let threads_pre = observed_threads();
    assert_eq!(
        threads_pre, threads_initial,
        "actual process thread count changed before wcsrtombs timing"
    );

    let results = cases
        .iter()
        .zip(expected_counts)
        .map(|(case, expected)| measure_case(host, fl, case, expected))
        .collect::<Vec<_>>();

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "actual process thread count changed during wcsrtombs timing"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("WCSRTOMBS_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));

    for result in &results {
        result.print(&incumbent_identity.path, threads_pre, threads_post);
    }
    let wins = results
        .iter()
        .filter(|result| result.comparison == "FL_FASTER")
        .count();
    let losses = results
        .iter()
        .filter(|result| result.comparison == "FL_SLOWER")
        .count();
    let undecidable = results.len() - wins - losses;
    let verdict = if results.iter().all(CaseResult::decidable) {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "WCSRTOMBS_COUNT_VERDICT symbol=wcsrtombs verdict={verdict} \
         comparable_cases={} wins={wins} losses={losses} undecidable={undecidable} \
         incomparable_multibyte_cases={incomparable} historical_cases=4 \
         threads_observed_pre={threads_pre} threads_observed_post={threads_post}",
        results.len(),
    );

    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}
