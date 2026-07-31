//! Machine-checkable incumbent conversion for held FrankenLibC performance claims.
//!
//! The first conversion is the deployed strict-mode `nl_langinfo` C-locale table
//! lookup. The historical row proved a large FrankenLibC self-speedup, but did
//! not time live glibc in the same invocation. This harness closes that evidence
//! gap without changing production code.
//!
//! Contract:
//! - host glibc is linked normally and FrankenLibC is loaded from the release
//!   artifact under `CARGO_TARGET_DIR` (or an explicit `--fl-so`);
//! - the benchmark and both serving ELF objects self-report SHA-256;
//! - all arms are proved to resolve to distinct objects and addresses;
//! - the complete supported C-locale table is byte-compared before timing;
//! - each case carries FL/FL and glibc/glibc A/A controls;
//! - the corrected gate uses the A/A median clause and twice the widest null
//!   CI half-width; A/A CI straddling is not a veto and CV is telemetry only;
//! - actual observed process threads and host-wide quiescence are reported.
//!
//! Build and run only from a clean committed base plus explicit overlays:
//! `RCH_REQUIRE_REMOTE=1 rch exec --base <commit> --clean-overlay \
//!  --overlay-path crates/frankenlibc-bench/Cargo.toml \
//!  --overlay-path crates/frankenlibc-bench/examples/incumbent_coverage_ab.rs -- \
//!  cargo run -j2 --profile release -p frankenlibc-bench --features abi-bench \
//!  --example incumbent_coverage_ab`

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use frankenlibc_bench::HostWideBenchmarkGuard;
use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUPS: usize = 4;
const REPS: usize = 2_000_000;
const BOOTSTRAP_RESAMPLES: usize = 4_096;
const NULL_BIAS_TOLERANCE: f64 = 0.02;

type NlLanginfoFn = unsafe extern "C" fn(libc::nl_item) -> *const c_char;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;

unsafe extern "C" {
    #[link_name = "nl_langinfo"]
    fn linked_host_nl_langinfo(item: libc::nl_item) -> *const c_char;
    #[link_name = "setlocale"]
    fn linked_host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}

const CODESET_CYCLE: &[libc::nl_item] = &[libc::CODESET];
const WEEKDAY_CYCLE: &[libc::nl_item] = &[
    libc::DAY_1,
    libc::DAY_2,
    libc::DAY_3,
    libc::DAY_4,
    libc::DAY_5,
    libc::DAY_6,
    libc::DAY_7,
    libc::DAY_1,
];
const MONTH_CYCLE: &[libc::nl_item] = &[
    libc::MON_1,
    libc::MON_2,
    libc::MON_3,
    libc::MON_4,
    libc::MON_5,
    libc::MON_6,
    libc::MON_7,
    libc::MON_8,
    libc::MON_9,
    libc::MON_10,
    libc::MON_11,
    libc::MON_12,
    libc::MON_1,
    libc::MON_2,
    libc::MON_3,
    libc::MON_4,
];
const FULL_TABLE_CYCLE: &[libc::nl_item] = &[
    libc::CODESET,
    libc::RADIXCHAR,
    libc::THOUSEP,
    libc::DAY_1,
    libc::DAY_2,
    libc::DAY_3,
    libc::DAY_4,
    libc::DAY_5,
    libc::DAY_6,
    libc::DAY_7,
    libc::ABDAY_1,
    libc::ABDAY_2,
    libc::ABDAY_3,
    libc::ABDAY_4,
    libc::ABDAY_5,
    libc::ABDAY_6,
    libc::ABDAY_7,
    libc::MON_1,
    libc::MON_2,
    libc::MON_3,
    libc::MON_4,
    libc::MON_5,
    libc::MON_6,
    libc::MON_7,
    libc::MON_8,
    libc::MON_9,
    libc::MON_10,
    libc::MON_11,
    libc::MON_12,
    libc::ABMON_1,
    libc::ABMON_2,
    libc::ABMON_3,
    libc::ABMON_4,
    libc::ABMON_5,
    libc::ABMON_6,
    libc::ABMON_7,
    libc::ABMON_8,
    libc::ABMON_9,
    libc::ABMON_10,
    libc::ABMON_11,
    libc::ABMON_12,
    libc::AM_STR,
    libc::PM_STR,
    libc::D_T_FMT,
    libc::D_FMT,
    libc::T_FMT,
    libc::T_FMT_AMPM,
    libc::ERA,
    libc::ERA_D_FMT,
    libc::ERA_D_T_FMT,
    libc::ERA_T_FMT,
    libc::ALT_DIGITS,
    libc::YESEXPR,
    libc::NOEXPR,
    libc::CRNCYSTR,
    262151,
    262152,
    262153,
    262154,
    262155,
    262156,
    262157,
    262158,
    libc::CODESET,
];

struct Config {
    fl_so: PathBuf,
    verify_only: bool,
    build_fl_if_missing: bool,
}

struct Case {
    label: &'static str,
    items: &'static [libc::nl_item],
    note: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "codeset",
        items: CODESET_CYCLE,
        note: "historical headline selector and common feature probe",
    },
    Case {
        label: "weekday_cycle",
        items: WEEKDAY_CYCLE,
        note: "rotating long C-locale day-name table entries",
    },
    Case {
        label: "month_cycle",
        items: MONTH_CYCLE,
        note: "rotating long C-locale month-name table entries",
    },
    Case {
        label: "full_table_cycle",
        items: FULL_TABLE_CYCLE,
        note: "all 63 supported selectors plus one CODESET repeat",
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
    fn decidable(&self) -> bool {
        matches!(self.comparison, "FL_FASTER" | "FL_SLOWER")
    }

    fn print(&self, incumbent_path: &Path, threads_pre: usize, threads_post: usize) {
        println!(
            "INCUMBENT_COVERAGE symbol=nl_langinfo case={} host={} \
             threads_observed_pre={} threads_observed_post={} samples={} \
             reps_per_arm={} fl_median_ns={:.3} glibc_median_ns={:.3} note={:?}",
            self.label,
            incumbent_path.display(),
            threads_pre,
            threads_post,
            SAMPLES - WARMUPS,
            REPS,
            self.fl_median_ns,
            self.glibc_median_ns,
            self.note,
        );
        println!(
            "INCUMBENT_COVERAGE_CONTRACT symbol=nl_langinfo case={} kind=null_fl_fl \
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
            "INCUMBENT_COVERAGE_CONTRACT symbol=nl_langinfo case={} \
             kind=null_glibc_glibc ratio_median={:.6} \
             ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} ratio_mad={:.6} \
             null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
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
            "INCUMBENT_COVERAGE_CONTRACT symbol=nl_langinfo case={} kind=fl_glibc \
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
                "unknown argument {arg:?}; usage: incumbent_coverage_ab \
                 [--fl-so PATH] [--verify-only]"
            );
        }
    }
    let build_fl_if_missing = fl_so.is_none();
    Config {
        fl_so: fl_so.unwrap_or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target"))
                .join("release/libfrankenlibc_abi.so")
        }),
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
        "rustup could not resolve the active Cargo: {}",
        String::from_utf8_lossy(&cargo_query.stderr)
    );
    let cargo = PathBuf::from(
        String::from_utf8(cargo_query.stdout)
            .expect("rustup cargo path is UTF-8")
            .trim(),
    );
    let build = Command::new(&cargo)
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
        "FL_BUILD source=clean_overlay_runtime_cargo builder={} artifact={}",
        cargo.display(),
        config.fl_so.display()
    );
}

fn observed_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|entries| entries.count())
        .unwrap_or(0)
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
fn run_batch(function: NlLanginfoFn, items: &[libc::nl_item], start: usize) -> usize {
    assert!(items.len().is_power_of_two());
    let mask = items.len() - 1;
    let mut accumulator = 0usize;
    for index in 0..REPS {
        let item = items[(index + start) & mask];
        let result = unsafe { function(black_box(item)) };
        accumulator = accumulator.wrapping_add(black_box(result) as usize);
    }
    black_box(accumulator)
}

fn time_batch(function: NlLanginfoFn, items: &[libc::nl_item], start: usize) -> f64 {
    let started = Instant::now();
    black_box(run_batch(function, items, start));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

fn measure_case(host: NlLanginfoFn, fl: NlLanginfoFn, case: &Case) -> CaseResult {
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
                    fa = time_batch(fl, case.items, sample);
                    fb = time_batch(fl, case.items, sample);
                }
                0 => {
                    fb = time_batch(fl, case.items, sample);
                    fa = time_batch(fl, case.items, sample);
                }
                1 if sample % 2 == 0 => {
                    ga = time_batch(host, case.items, sample);
                    gb = time_batch(host, case.items, sample);
                }
                1 => {
                    gb = time_batch(host, case.items, sample);
                    ga = time_batch(host, case.items, sample);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_batch(fl, case.items, sample);
                    effect_glibc = time_batch(host, case.items, sample);
                }
                2 => {
                    effect_glibc = time_batch(host, case.items, sample);
                    effect_fl = time_batch(fl, case.items, sample);
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
    assert!(
        std::env::var_os("FRANKENLIBC_MODE").is_none_or(|mode| mode == OsStr::new("strict")),
        "incumbent conversion must run with FRANKENLIBC_MODE=strict or the strict default"
    );

    let benchmark_identity =
        sha256_file(&std::env::current_exe().expect("resolve benchmark executable"))
            .expect("hash benchmark executable");
    print_identity("BENCH_ELF", &benchmark_identity);
    println!(
        "HOST_IDENTITY hostname={} loadavg={} pid={}",
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
        std::process::id(),
    );

    let host_locale = unsafe { linked_host_setlocale(libc::LC_ALL, c"C".as_ptr()) };
    assert!(!host_locale.is_null(), "host setlocale(LC_ALL, C) failed");

    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_symbol = unsafe { libc::dlsym(handle, c"nl_langinfo".as_ptr()) };
    assert!(
        !fl_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC nl_langinfo")
    );
    let fl_setlocale_symbol = unsafe { libc::dlsym(handle, c"setlocale".as_ptr()) };
    assert!(
        !fl_setlocale_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC setlocale")
    );

    let host: NlLanginfoFn = linked_host_nl_langinfo;
    let fl: NlLanginfoFn = unsafe { std::mem::transmute(fl_symbol) };
    let fl_setlocale: SetlocaleFn = unsafe { std::mem::transmute(fl_setlocale_symbol) };
    let fl_locale = unsafe { fl_setlocale(libc::LC_ALL, c"C".as_ptr()) };
    assert!(
        !fl_locale.is_null(),
        "FrankenLibC setlocale(LC_ALL, C) failed"
    );

    let incumbent_identity = symbol_object(host as *const () as *const c_void)
        .expect("identify host nl_langinfo object");
    let fl_identity =
        symbol_object(fl_symbol.cast_const()).expect("identify FrankenLibC nl_langinfo object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=nl_langinfo");
    println!("FL_LINKAGE explicit_dlopen_local symbol=nl_langinfo");
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
    println!(
        "ARM_DISTINCT symbol=nl_langinfo incumbent_address={:#x} fl_address={:#x}",
        host as usize, fl as usize,
    );

    let mut conformance_comparisons = 0usize;
    for &item in FULL_TABLE_CYCLE {
        let host_result = unsafe { host(item) };
        let fl_result = unsafe { fl(item) };
        assert!(
            !host_result.is_null() && !fl_result.is_null(),
            "nl_langinfo returned NULL for supported selector {item}"
        );
        let host_bytes = unsafe { CStr::from_ptr(host_result) }.to_bytes_with_nul();
        let fl_bytes = unsafe { CStr::from_ptr(fl_result) }.to_bytes_with_nul();
        assert_eq!(
            fl_bytes, host_bytes,
            "nl_langinfo C-locale mismatch for selector {item}"
        );
        conformance_comparisons += 1;
    }
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=nl_langinfo locale=C \
         supported_selectors=63 comparisons={conformance_comparisons} verdict=pass"
    );
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=nl_langinfo verdict=pass");
        return;
    }

    let guard = HostWideBenchmarkGuard::new().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=guard_init error={error}");
        std::process::exit(2);
    });
    let pre = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=pre_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", pre.contract_line("pre_measurement"));
    let threads_pre = observed_threads();
    assert_eq!(
        threads_pre, 1,
        "nl_langinfo benchmark requires one actually observed process thread"
    );

    let results = CASES
        .iter()
        .map(|case| measure_case(host, fl, case))
        .collect::<Vec<_>>();

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, 1,
        "nl_langinfo benchmark requires one actually observed process thread"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
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
    let headline = results
        .iter()
        .find(|result| result.label == "full_table_cycle")
        .expect("missing full_table_cycle result");
    let verdict = if results.iter().all(CaseResult::decidable) {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=nl_langinfo verdict={verdict} \
         cases={} wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=full_table_cycle headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        results.len(),
        headline.effect_median,
        headline.comparison,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}
