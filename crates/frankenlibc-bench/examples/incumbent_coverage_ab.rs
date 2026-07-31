//! Machine-checkable incumbent conversion for held FrankenLibC performance claims.
//!
//! The first conversions are the deployed strict-mode `nl_langinfo` C-locale
//! lookup, `getrandom` syscall wrapper, `getauxval` snapshot, waiter-aware
//! `sem_post`, inlined `thrd_current`, strict `mtx_trylock`, and hosts-backed
//! `getaddrinfo`, `gethostbyaddr`, and `gethostbyname`, the coupled f32
//! `sinhf`/`coshf` paths, and the exact `snprintf` `%u`/`%p`/`%c` emitters.
//! Their historical rows proved FrankenLibC self-speedups, but did not time
//! live glibc in the same invocation -- or, for `snprintf`, quoted a glibc
//! number from an `abi-bench` Criterion binary whose interposed allocator and
//! symbol resolution are exactly the hazard this harness exists to remove.
//! This harness closes those evidence gaps without changing production code.
//!
//! Contract:
//! - host glibc is linked normally and FrankenLibC is loaded from the release
//!   artifact under `FRANKENLIBC_BENCH_TARGET_DIR`, `CARGO_TARGET_DIR`, or an
//!   explicit `--fl-so`, in that precedence order;
//! - the benchmark and both serving ELF objects self-report SHA-256;
//! - all arms are proved to resolve to distinct objects and addresses;
//! - each family runs its complete pre-timing conformance contract;
//! - each case carries FL/FL and glibc/glibc A/A controls;
//! - the corrected gate uses the A/A median clause and twice the widest null
//!   CI half-width; A/A CI straddling is not a veto and CV is telemetry only;
//! - 36 retained samples exactly balance all six phase/order cells;
//! - actual observed process threads and host-wide quiescence are reported.
//!
//! Build and run only from a clean committed base plus explicit overlays:
//! `RCH_REQUIRE_REMOTE=1 rch exec --base <commit> --clean-overlay \
//!  --overlay-path crates/frankenlibc-bench/examples/incumbent_coverage_ab.rs -- \
//!  env -u CARGO_TARGET_DIR \
//!  FRANKENLIBC_BENCH_TARGET_DIR=/data/tmp/cargo-target-frankenlibc \
//!  cargo --config 'build.target-dir="/data/tmp/cargo-target-frankenlibc"' \
//!  run -j2 --profile release -p frankenlibc-bench --features abi-bench \
//!  --example incumbent_coverage_ab -- \
//!  --family \
//!  nl_langinfo|getrandom|getauxval|sem_post|thrd_current|mtx_trylock|\
//!  getaddrinfo_hosts|sinhf_coshf|gethostbyaddr|gethostbyname|snprintf`
//!
//! On a shared fleet add `--pin-quietest N` and drive several conversions from
//! one build with `--families a,b,c` (each family runs in a fresh child).
//! The quiet gate keys on the process's own allowed cpuset, so pinning narrows
//! what must be quiet without weakening the gate: same 20% ceiling, same five
//! consecutive clear samples, same affinity tripwire, and the contract line
//! records `allowed_cpus`/`affinity_mask` so the scope stays auditable.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_uint, c_ulong, c_void};
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
const NLLANGINFO_REPS: usize = 2_000_000;
const GETRANDOM_REPS: usize = 50_000;
const GETAUXVAL_REPS: usize = 2_000_000;
const SEM_POST_REPS: usize = 1_000_000;
const THRD_CURRENT_REPS: usize = 4_000_000;
const MTX_TRYLOCK_REPS: usize = 1_000_000;
const GETADDRINFO_HOSTS_REPS: usize = 2_000;
const F32_HYPERBOLIC_REPS: usize = 200_000;
const GETHOSTBYADDR_REPS: usize = 5_000;
const GETHOSTBYNAME_REPS: usize = 5_000;
const SNPRINTF_REPS: usize = 200_000;
const BOOTSTRAP_RESAMPLES: usize = 4_096;
const NULL_BIAS_TOLERANCE: f64 = 0.02;
const IPV4_LOOPBACK: [u8; 4] = [127, 0, 0, 1];

type NlLanginfoFn = unsafe extern "C" fn(libc::nl_item) -> *const c_char;
type SetlocaleFn = unsafe extern "C" fn(c_int, *const c_char) -> *mut c_char;
type GetrandomFn = unsafe extern "C" fn(*mut c_void, usize, c_uint) -> isize;
type GetauxvalFn = unsafe extern "C" fn(c_ulong) -> c_ulong;
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;
type SemInitFn = unsafe extern "C" fn(*mut libc::sem_t, c_int, c_uint) -> c_int;
type SemDestroyFn = unsafe extern "C" fn(*mut libc::sem_t) -> c_int;
type SemPostFn = unsafe extern "C" fn(*mut libc::sem_t) -> c_int;
type SemTrywaitFn = unsafe extern "C" fn(*mut libc::sem_t) -> c_int;
type ThrdCurrentFn = unsafe extern "C" fn() -> libc::pthread_t;
type MtxInitFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t, c_int) -> c_int;
type MtxTrylockFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type MtxUnlockFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t) -> c_int;
type MtxDestroyFn = unsafe extern "C" fn(*mut libc::pthread_mutex_t);
type GetaddrinfoFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> c_int;
type FreeaddrinfoFn = unsafe extern "C" fn(*mut libc::addrinfo);
type F32UnaryFn = unsafe extern "C" fn(f32) -> f32;
type GethostbyaddrFn =
    unsafe extern "C" fn(*const c_void, libc::socklen_t, c_int) -> *mut libc::hostent;
type GethostbynameFn = unsafe extern "C" fn(*const c_char) -> *mut libc::hostent;
/// True C-variadic pointer type. Declaring `snprintf` with a fixed arity would
/// leave `AL` (the SysV vector-register count) unset at the call site, so the
/// two arms could diverge on register-save work that has nothing to do with the
/// formatter under test. The variadic type makes both arms use the real ABI.
type SnprintfFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;

unsafe extern "C" {
    #[link_name = "nl_langinfo"]
    fn linked_host_nl_langinfo(item: libc::nl_item) -> *const c_char;
    #[link_name = "setlocale"]
    fn linked_host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    #[link_name = "getrandom"]
    fn linked_host_getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize;
    #[link_name = "getauxval"]
    fn linked_host_getauxval(type_: c_ulong) -> c_ulong;
    #[link_name = "__errno_location"]
    fn linked_host_errno_location() -> *mut c_int;
    #[link_name = "sem_init"]
    fn linked_host_sem_init(sem: *mut libc::sem_t, pshared: c_int, value: c_uint) -> c_int;
    #[link_name = "sem_destroy"]
    fn linked_host_sem_destroy(sem: *mut libc::sem_t) -> c_int;
    #[link_name = "sem_post"]
    fn linked_host_sem_post(sem: *mut libc::sem_t) -> c_int;
    #[link_name = "sem_trywait"]
    fn linked_host_sem_trywait(sem: *mut libc::sem_t) -> c_int;
    #[link_name = "thrd_current"]
    fn linked_host_thrd_current() -> libc::pthread_t;
    #[link_name = "mtx_init"]
    fn linked_host_mtx_init(mtx: *mut libc::pthread_mutex_t, typ: c_int) -> c_int;
    #[link_name = "mtx_trylock"]
    fn linked_host_mtx_trylock(mtx: *mut libc::pthread_mutex_t) -> c_int;
    #[link_name = "mtx_unlock"]
    fn linked_host_mtx_unlock(mtx: *mut libc::pthread_mutex_t) -> c_int;
    #[link_name = "mtx_destroy"]
    fn linked_host_mtx_destroy(mtx: *mut libc::pthread_mutex_t);
    #[link_name = "getaddrinfo"]
    fn linked_host_getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const libc::addrinfo,
        result: *mut *mut libc::addrinfo,
    ) -> c_int;
    #[link_name = "freeaddrinfo"]
    fn linked_host_freeaddrinfo(result: *mut libc::addrinfo);
    #[link_name = "sinhf"]
    fn linked_host_sinhf(value: f32) -> f32;
    #[link_name = "coshf"]
    fn linked_host_coshf(value: f32) -> f32;
    #[link_name = "gethostbyaddr"]
    fn linked_host_gethostbyaddr(
        address: *const c_void,
        length: libc::socklen_t,
        family: c_int,
    ) -> *mut libc::hostent;
    #[link_name = "gethostbyname"]
    fn linked_host_gethostbyname(name: *const c_char) -> *mut libc::hostent;
    #[link_name = "snprintf"]
    fn linked_host_snprintf(
        s: *mut c_char,
        n: usize,
        format: *const c_char,
        ...
    ) -> c_int;
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

const fn hyperbolic_mid_inputs() -> [f32; 64] {
    let mut inputs = [0.0; 64];
    let mut index = 0;
    while index < inputs.len() {
        inputs[index] = 0.5 + index as f32 * 0.1;
        index += 1;
    }
    inputs
}

const HYPERBOLIC_MID_INPUTS: [f32; 64] = hyperbolic_mid_inputs();
const HYPERBOLIC_SPECIAL_INPUTS: &[f32] = &[
    0.0,
    -0.0,
    f32::INFINITY,
    f32::NEG_INFINITY,
    f32::NAN,
    1.0,
    -1.0,
    0.5,
    20.0,
    -20.0,
    710.0,
    -710.0,
    1.0e-10,
];

struct Config {
    fl_so: PathBuf,
    target_dir: PathBuf,
    verify_only: bool,
    build_fl_if_missing: bool,
    family: Family,
    /// Narrow this process to the N quietest logical CPUs before the guard is
    /// constructed. Zero leaves affinity untouched.
    pin_quietest: usize,
    /// Parent mode: run each named family in its own fresh child process.
    families: Vec<String>,
}

#[derive(Clone, Copy)]
enum Family {
    NlLanginfo,
    Getrandom,
    Getauxval,
    SemPost,
    ThrdCurrent,
    MtxTrylock,
    GetaddrinfoHosts,
    SinhfCoshf,
    Gethostbyaddr,
    Gethostbyname,
    Snprintf,
}

struct Case {
    label: &'static str,
    items: &'static [libc::nl_item],
    note: &'static str,
}

struct GetrandomCase {
    label: &'static str,
    length: usize,
    flags: c_uint,
    note: &'static str,
}

struct GetauxvalCase {
    label: &'static str,
    type_: c_ulong,
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

const GETRANDOM_CASES: &[GetrandomCase] = &[
    GetrandomCase {
        label: "zero_bytes",
        length: 0,
        flags: 0,
        note: "zero-length ABI boundary without a payload write",
    },
    GetrandomCase {
        label: "one_byte",
        length: 1,
        flags: 0,
        note: "minimum non-empty successful request",
    },
    GetrandomCase {
        label: "thirty_two_bytes",
        length: 32,
        flags: 0,
        note: "historical headline request and common CSPRNG seed size",
    },
    GetrandomCase {
        label: "two_fifty_six_bytes",
        length: 256,
        flags: 0,
        note: "largest Linux request guaranteed not to short-read once initialized",
    },
];

const GETAUXVAL_CASES: &[GetauxvalCase] = &[
    GetauxvalCase {
        label: "pagesz",
        type_: libc::AT_PAGESZ as c_ulong,
        note: "historical headline and warm present scalar",
    },
    GetauxvalCase {
        label: "phnum",
        type_: libc::AT_PHNUM as c_ulong,
        note: "warm present scalar from the executable image",
    },
    GetauxvalCase {
        label: "uid_present_zero",
        type_: libc::AT_UID as c_ulong,
        note: "warm present-zero scalar with errno preservation",
    },
    GetauxvalCase {
        label: "secure_present_zero",
        type_: libc::AT_SECURE as c_ulong,
        note: "warm present-zero security flag with errno preservation",
    },
    GetauxvalCase {
        label: "random_pointer",
        type_: libc::AT_RANDOM as c_ulong,
        note: "warm present pointer-valued entry",
    },
    GetauxvalCase {
        label: "missing_cached",
        type_: 63,
        note: "warm absent key below the 64-slot cache boundary",
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
    reps_per_arm: usize,
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

    fn print(&self, symbol: &str, incumbent_path: &Path, threads_pre: usize, threads_post: usize) {
        println!(
            "INCUMBENT_COVERAGE symbol={symbol} case={} host={} \
             threads_observed_pre={} threads_observed_post={} samples={} \
             reps_per_arm={} fl_median_ns={:.3} glibc_median_ns={:.3} note={:?}",
            self.label,
            incumbent_path.display(),
            threads_pre,
            threads_post,
            SAMPLES - WARMUPS,
            self.reps_per_arm,
            self.fl_median_ns,
            self.glibc_median_ns,
            self.note,
        );
        println!(
            "INCUMBENT_COVERAGE_CONTRACT symbol={symbol} case={} kind=null_fl_fl \
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
            "INCUMBENT_COVERAGE_CONTRACT symbol={symbol} case={} \
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
            "INCUMBENT_COVERAGE_CONTRACT symbol={symbol} case={} kind=fl_glibc \
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
    let mut family = Family::NlLanginfo;
    let mut pin_quietest = 0usize;
    let mut families = Vec::new();
    while let Some(arg) = args.next() {
        if arg == "--fl-so" {
            fl_so = args.next().map(PathBuf::from);
        } else if arg == "--verify-only" {
            verify_only = true;
        } else if arg == "--pin-quietest" {
            pin_quietest = args
                .next()
                .expect("--pin-quietest needs a logical-CPU count")
                .to_string_lossy()
                .parse()
                .expect("--pin-quietest needs an integer");
        } else if arg == "--families" {
            families = args
                .next()
                .expect("--families needs a comma-separated list")
                .to_string_lossy()
                .split(',')
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect();
        } else if arg == "--family" {
            family = match args.next().as_deref() {
                Some(value) if value == OsStr::new("nl_langinfo") => Family::NlLanginfo,
                Some(value) if value == OsStr::new("getrandom") => Family::Getrandom,
                Some(value) if value == OsStr::new("getauxval") => Family::Getauxval,
                Some(value) if value == OsStr::new("sem_post") => Family::SemPost,
                Some(value) if value == OsStr::new("thrd_current") => Family::ThrdCurrent,
                Some(value) if value == OsStr::new("mtx_trylock") => Family::MtxTrylock,
                Some(value) if value == OsStr::new("getaddrinfo_hosts") => Family::GetaddrinfoHosts,
                Some(value) if value == OsStr::new("sinhf_coshf") => Family::SinhfCoshf,
                Some(value) if value == OsStr::new("gethostbyaddr") => Family::Gethostbyaddr,
                Some(value) if value == OsStr::new("gethostbyname") => Family::Gethostbyname,
                Some(value) if value == OsStr::new("snprintf") => Family::Snprintf,
                value => panic!(
                    "unknown family {value:?}; expected nl_langinfo, getrandom, getauxval, \
                     sem_post, thrd_current, mtx_trylock, getaddrinfo_hosts, sinhf_coshf, \
                     gethostbyaddr, gethostbyname, or snprintf"
                ),
            };
        } else {
            panic!(
                "unknown argument {arg:?}; usage: incumbent_coverage_ab \
                 [--fl-so PATH] [--verify-only] [--pin-quietest N] \
                 [--families a,b,c] \
                 [--family \
                  nl_langinfo|getrandom|getauxval|sem_post|thrd_current|mtx_trylock|\
                  getaddrinfo_hosts|sinhf_coshf|gethostbyaddr|gethostbyname|snprintf]"
            );
        }
    }
    let build_fl_if_missing = fl_so.is_none();
    let target_dir = std::env::var_os("FRANKENLIBC_BENCH_TARGET_DIR")
        .or_else(|| std::env::var_os("CARGO_TARGET_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    let fl_so = fl_so.unwrap_or_else(|| target_dir.join("release/libfrankenlibc_abi.so"));
    Config {
        fl_so,
        target_dir,
        verify_only,
        build_fl_if_missing,
        family,
        pin_quietest,
        families,
    }
}

/// Logical CPUs this process is currently allowed to run on.
fn current_affinity() -> Vec<usize> {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let status =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    assert_eq!(status, 0, "sched_getaffinity failed");
    (0..libc::CPU_SETSIZE as usize)
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
        .collect()
}

/// Busy fraction per logical CPU across one `/proc/stat` window.
fn cpu_busy_fractions(window: std::time::Duration) -> BTreeMap<usize, f64> {
    fn snapshot() -> BTreeMap<usize, (u64, u64)> {
        let mut counters = BTreeMap::new();
        let stat = std::fs::read_to_string("/proc/stat").expect("read /proc/stat");
        for line in stat.lines() {
            let Some(rest) = line.strip_prefix("cpu") else {
                continue;
            };
            let mut fields = rest.split_whitespace();
            let Some(index) = fields.next() else { continue };
            let Ok(cpu) = index.parse::<usize>() else {
                continue;
            };
            let values = fields.filter_map(|v| v.parse::<u64>().ok()).collect::<Vec<_>>();
            if values.len() >= 4 {
                counters.insert(cpu, (values.iter().sum::<u64>(), values[3]));
            }
        }
        counters
    }

    let before = snapshot();
    std::thread::sleep(window);
    let after = snapshot();
    let mut busy = BTreeMap::new();
    for (&cpu, &(total_before, idle_before)) in &before {
        let Some(&(total_after, idle_after)) = after.get(&cpu) else {
            continue;
        };
        let total_delta = total_after.saturating_sub(total_before);
        let idle_delta = idle_after.saturating_sub(idle_before);
        let fraction = if total_delta > 0 {
            (total_delta - idle_delta) as f64 / total_delta as f64
        } else {
            1.0
        };
        busy.insert(cpu, fraction);
    }
    busy
}

/// Narrow this process to the `width` quietest logical CPUs it is already
/// allowed to use.
///
/// This does NOT weaken the quiet gate. `HostWideBenchmarkGuard` keys on the
/// process's own allowed cpuset, so on a shared fleet an unpinned run demands
/// that every logical CPU on the box sit below the same 20% ceiling -- which is
/// what failed closed, with zero samples, on four ledger rows. Narrowing scopes
/// the set that must be quiet; the ceiling, the five-consecutive-clear-samples
/// requirement, and the affinity-change tripwire are all unchanged, and the
/// guard's contract line reports `allowed_cpus` and `affinity_mask` so the
/// scope is auditable.
fn pin_to_quietest(width: usize) {
    let allowed = current_affinity();
    if width == 0 || width >= allowed.len() {
        println!(
            "PIN_QUIETEST requested_width={width} action=none allowed_cpu_count={} \
             reason=width_not_narrower",
            allowed.len(),
        );
        return;
    }

    let busy = cpu_busy_fractions(std::time::Duration::from_secs(2));
    let mut ranked = allowed
        .iter()
        .map(|&cpu| (cpu, busy.get(&cpu).copied().unwrap_or(1.0)))
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let chosen = &ranked[..width];

    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_ZERO(&mut set) };
    for &(cpu, _) in chosen {
        unsafe { libc::CPU_SET(cpu, &mut set) };
    }
    let status =
        unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
    assert_eq!(status, 0, "sched_setaffinity failed");

    let ranking = ranked
        .iter()
        .map(|(cpu, fraction)| format!("{cpu}:{fraction:.3}"))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "PIN_QUIETEST requested_width={width} action=narrowed selected_cpus={} \
         selected_busy={} allowed_before={} sample_window_ms=2000 busy_ranking=[{ranking}]",
        chosen
            .iter()
            .map(|(cpu, _)| cpu.to_string())
            .collect::<Vec<_>>()
            .join("+"),
        chosen
            .iter()
            .map(|(_, fraction)| format!("{fraction:.3}"))
            .collect::<Vec<_>>()
            .join("+"),
        allowed.len(),
    );
}

/// Parent mode: run each family in its own fresh process.
///
/// One process per family keeps each measurement's conditions identical to the
/// single-family rows already in the ledger -- notably the observed-thread
/// assertions, which a resolver family could otherwise perturb for a math
/// family that ran after it in the same process.
fn run_families(config: &Config) -> ! {
    let executable = std::env::current_exe().expect("resolve benchmark executable");
    let mut statuses = Vec::new();
    for family in &config.families {
        println!("FAMILY_CHILD_BEGIN family={family}");
        let mut command = Command::new(&executable);
        command.arg("--family").arg(family);
        command.arg("--fl-so").arg(&config.fl_so);
        if config.verify_only {
            command.arg("--verify-only");
        }
        if config.pin_quietest > 0 {
            command.arg("--pin-quietest").arg(config.pin_quietest.to_string());
        }
        let status = command.status().expect("spawn family child");
        let code = status.code().unwrap_or(-1);
        println!("FAMILY_CHILD_END family={family} status={code}");
        statuses.push((family.clone(), code));
    }
    let decided = statuses.iter().filter(|(_, code)| *code == 0).count();
    println!(
        "FAMILY_RUN_SUMMARY families={} decided={decided} blocked={} detail={}",
        statuses.len(),
        statuses.len() - decided,
        statuses
            .iter()
            .map(|(family, code)| format!("{family}={code}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    std::process::exit(i32::from(decided != statuses.len()));
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
    for index in 0..NLLANGINFO_REPS {
        let item = items[(index + start) & mask];
        let result = unsafe { function(black_box(item)) };
        accumulator = accumulator.wrapping_add(black_box(result) as usize);
    }
    black_box(accumulator)
}

fn time_batch(function: NlLanginfoFn, items: &[libc::nl_item], start: usize) -> f64 {
    let started = Instant::now();
    black_box(run_batch(function, items, start));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / NLLANGINFO_REPS as f64
}

#[allow(clippy::too_many_arguments)]
fn summarize_case(
    label: &'static str,
    note: &'static str,
    reps_per_arm: usize,
    fl_effect: Vec<f64>,
    glibc_effect: Vec<f64>,
    fl_null_a: Vec<f64>,
    fl_null_b: Vec<f64>,
    glibc_null_a: Vec<f64>,
    glibc_null_b: Vec<f64>,
) -> CaseResult {
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
        label,
        note,
        reps_per_arm,
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

    summarize_case(
        case.label,
        case.note,
        NLLANGINFO_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_getrandom_batch(function: GetrandomFn, length: usize, flags: c_uint) -> isize {
    let mut buffer = [0u8; 256];
    let mut total = 0isize;
    for _ in 0..GETRANDOM_REPS {
        let result = unsafe {
            function(
                black_box(buffer.as_mut_ptr().cast()),
                black_box(length),
                black_box(flags),
            )
        };
        total = total.wrapping_add(black_box(result));
    }
    black_box(buffer);
    black_box(total)
}

fn time_getrandom_batch(function: GetrandomFn, case: &GetrandomCase) -> f64 {
    let started = Instant::now();
    let total = run_getrandom_batch(function, case.length, case.flags);
    let elapsed = started.elapsed().as_secs_f64() * 1_000_000_000.0 / GETRANDOM_REPS as f64;
    assert_eq!(
        total,
        case.length as isize * GETRANDOM_REPS as isize,
        "getrandom timed batch returned a short read or error for {}",
        case.label,
    );
    elapsed
}

fn measure_getrandom_case(host: GetrandomFn, fl: GetrandomFn, case: &GetrandomCase) -> CaseResult {
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
                    fa = time_getrandom_batch(fl, case);
                    fb = time_getrandom_batch(fl, case);
                }
                0 => {
                    fb = time_getrandom_batch(fl, case);
                    fa = time_getrandom_batch(fl, case);
                }
                1 if sample % 2 == 0 => {
                    ga = time_getrandom_batch(host, case);
                    gb = time_getrandom_batch(host, case);
                }
                1 => {
                    gb = time_getrandom_batch(host, case);
                    ga = time_getrandom_batch(host, case);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_getrandom_batch(fl, case);
                    effect_glibc = time_getrandom_batch(host, case);
                }
                2 => {
                    effect_glibc = time_getrandom_batch(host, case);
                    effect_fl = time_getrandom_batch(fl, case);
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

    summarize_case(
        case.label,
        case.note,
        GETRANDOM_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_getauxval_batch(function: GetauxvalFn, type_: c_ulong) -> c_ulong {
    let mut total = 0 as c_ulong;
    for _ in 0..GETAUXVAL_REPS {
        let result = unsafe { function(black_box(type_)) };
        total = total.wrapping_add(black_box(result));
    }
    black_box(total)
}

fn time_getauxval_batch(function: GetauxvalFn, case: &GetauxvalCase) -> f64 {
    let started = Instant::now();
    black_box(run_getauxval_batch(function, case.type_));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / GETAUXVAL_REPS as f64
}

fn measure_getauxval_case(host: GetauxvalFn, fl: GetauxvalFn, case: &GetauxvalCase) -> CaseResult {
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
                    fa = time_getauxval_batch(fl, case);
                    fb = time_getauxval_batch(fl, case);
                }
                0 => {
                    fb = time_getauxval_batch(fl, case);
                    fa = time_getauxval_batch(fl, case);
                }
                1 if sample % 2 == 0 => {
                    ga = time_getauxval_batch(host, case);
                    gb = time_getauxval_batch(host, case);
                }
                1 => {
                    gb = time_getauxval_batch(host, case);
                    ga = time_getauxval_batch(host, case);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_getauxval_batch(fl, case);
                    effect_glibc = time_getauxval_batch(host, case);
                }
                2 => {
                    effect_glibc = time_getauxval_batch(host, case);
                    effect_fl = time_getauxval_batch(fl, case);
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

    summarize_case(
        case.label,
        case.note,
        GETAUXVAL_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_sem_post_batch(post: SemPostFn, trywait: SemTrywaitFn, sem: *mut libc::sem_t) -> i64 {
    let mut total = 0i64;
    for _ in 0..SEM_POST_REPS {
        let post_result = unsafe { post(black_box(sem)) };
        let trywait_result = unsafe { trywait(black_box(sem)) };
        total = total
            .wrapping_add(black_box(post_result) as i64)
            .wrapping_add(black_box(trywait_result) as i64);
    }
    black_box(total)
}

fn time_sem_post_batch(post: SemPostFn, trywait: SemTrywaitFn, sem: *mut libc::sem_t) -> f64 {
    let started = Instant::now();
    let total = run_sem_post_batch(post, trywait, sem);
    let elapsed = started.elapsed().as_secs_f64() * 1_000_000_000.0 / SEM_POST_REPS as f64;
    assert_eq!(
        total, 0,
        "sem_post + sem_trywait timed cycle returned an error"
    );
    elapsed
}

fn measure_sem_post_case(
    host_post: SemPostFn,
    host_trywait: SemTrywaitFn,
    host_sem: *mut libc::sem_t,
    fl_post: SemPostFn,
    fl_trywait: SemTrywaitFn,
    fl_sem: *mut libc::sem_t,
) -> CaseResult {
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
                    fa = time_sem_post_batch(fl_post, fl_trywait, fl_sem);
                    fb = time_sem_post_batch(fl_post, fl_trywait, fl_sem);
                }
                0 => {
                    fb = time_sem_post_batch(fl_post, fl_trywait, fl_sem);
                    fa = time_sem_post_batch(fl_post, fl_trywait, fl_sem);
                }
                1 if sample % 2 == 0 => {
                    ga = time_sem_post_batch(host_post, host_trywait, host_sem);
                    gb = time_sem_post_batch(host_post, host_trywait, host_sem);
                }
                1 => {
                    gb = time_sem_post_batch(host_post, host_trywait, host_sem);
                    ga = time_sem_post_batch(host_post, host_trywait, host_sem);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_sem_post_batch(fl_post, fl_trywait, fl_sem);
                    effect_glibc = time_sem_post_batch(host_post, host_trywait, host_sem);
                }
                2 => {
                    effect_glibc = time_sem_post_batch(host_post, host_trywait, host_sem);
                    effect_fl = time_sem_post_batch(fl_post, fl_trywait, fl_sem);
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

    summarize_case(
        "uncontended_cycle",
        "historical sem_post plus sem_trywait token round trip",
        SEM_POST_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_thrd_current_batch(function: ThrdCurrentFn) -> usize {
    let mut accumulator = 0usize;
    for _ in 0..THRD_CURRENT_REPS {
        let thread = unsafe { black_box(function)() };
        accumulator = accumulator.wrapping_add(black_box(thread as usize));
    }
    black_box(accumulator)
}

fn time_thrd_current_batch(function: ThrdCurrentFn) -> f64 {
    let started = Instant::now();
    black_box(run_thrd_current_batch(function));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / THRD_CURRENT_REPS as f64
}

fn measure_thrd_current_case(host: ThrdCurrentFn, fl: ThrdCurrentFn) -> CaseResult {
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
                    fa = time_thrd_current_batch(fl);
                    fb = time_thrd_current_batch(fl);
                }
                0 => {
                    fb = time_thrd_current_batch(fl);
                    fa = time_thrd_current_batch(fl);
                }
                1 if sample % 2 == 0 => {
                    ga = time_thrd_current_batch(host);
                    gb = time_thrd_current_batch(host);
                }
                1 => {
                    gb = time_thrd_current_batch(host);
                    ga = time_thrd_current_batch(host);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_thrd_current_batch(fl);
                    effect_glibc = time_thrd_current_batch(host);
                }
                2 => {
                    effect_glibc = time_thrd_current_batch(host);
                    effect_fl = time_thrd_current_batch(fl);
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

    summarize_case(
        "current_identity",
        "historical current-thread identity-cache lookup",
        THRD_CURRENT_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_mtx_trylock_batch(function: MtxTrylockFn, mutex: *mut libc::pthread_mutex_t) -> usize {
    let mut accumulator = 0usize;
    for _ in 0..MTX_TRYLOCK_REPS {
        let rc = unsafe { black_box(function)(black_box(mutex)) };
        accumulator = accumulator.wrapping_add(black_box(rc as usize));
    }
    black_box(accumulator)
}

fn time_mtx_trylock_batch(function: MtxTrylockFn, mutex: *mut libc::pthread_mutex_t) -> f64 {
    let started = Instant::now();
    let accumulator = run_mtx_trylock_batch(function, mutex);
    let elapsed = started.elapsed().as_secs_f64();
    assert_eq!(
        accumulator, MTX_TRYLOCK_REPS,
        "mtx_trylock busy-path batch returned a non-busy result"
    );
    elapsed * 1_000_000_000.0 / MTX_TRYLOCK_REPS as f64
}

fn measure_mtx_trylock_case(
    host: MtxTrylockFn,
    fl: MtxTrylockFn,
    host_mutex: *mut libc::pthread_mutex_t,
    fl_mutex: *mut libc::pthread_mutex_t,
) -> CaseResult {
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
                    fa = time_mtx_trylock_batch(fl, fl_mutex);
                    fb = time_mtx_trylock_batch(fl, fl_mutex);
                }
                0 => {
                    fb = time_mtx_trylock_batch(fl, fl_mutex);
                    fa = time_mtx_trylock_batch(fl, fl_mutex);
                }
                1 if sample % 2 == 0 => {
                    ga = time_mtx_trylock_batch(host, host_mutex);
                    gb = time_mtx_trylock_batch(host, host_mutex);
                }
                1 => {
                    gb = time_mtx_trylock_batch(host, host_mutex);
                    ga = time_mtx_trylock_batch(host, host_mutex);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_mtx_trylock_batch(fl, fl_mutex);
                    effect_glibc = time_mtx_trylock_batch(host, host_mutex);
                }
                2 => {
                    effect_glibc = time_mtx_trylock_batch(host, host_mutex);
                    effect_fl = time_mtx_trylock_batch(fl, fl_mutex);
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

    summarize_case(
        "already_owned_busy",
        "historical already-owned plain-mutex busy path",
        MTX_TRYLOCK_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

fn hosts_getaddrinfo_hints() -> libc::addrinfo {
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = libc::AF_INET;
    hints.ai_socktype = libc::SOCK_STREAM;
    hints.ai_protocol = libc::IPPROTO_TCP;
    hints.ai_flags = libc::AI_NUMERICSERV;
    hints
}

fn consume_addrinfo(mut result: *mut libc::addrinfo) -> u64 {
    let mut accumulator = 0xcbf2_9ce4_8422_2325u64;
    while !result.is_null() {
        let current = unsafe { &*result };
        accumulator ^= current.ai_family as u64;
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
        accumulator ^= current.ai_socktype as u64;
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
        accumulator ^= current.ai_protocol as u64;
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
        if current.ai_family == libc::AF_INET && !current.ai_addr.is_null() {
            let address = unsafe { &*current.ai_addr.cast::<libc::sockaddr_in>() };
            accumulator ^= u64::from(address.sin_addr.s_addr);
            accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
            accumulator ^= u64::from(address.sin_port);
            accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
        }
        result = current.ai_next;
    }
    black_box(accumulator)
}

#[inline(never)]
fn run_getaddrinfo_hosts_batch(
    getaddrinfo: GetaddrinfoFn,
    freeaddrinfo: FreeaddrinfoFn,
    hints: &libc::addrinfo,
    node: &CStr,
) -> u64 {
    let mut accumulator = 0u64;
    for _ in 0..GETADDRINFO_HOSTS_REPS {
        let mut result = std::ptr::null_mut();
        let rc = unsafe {
            black_box(getaddrinfo)(
                black_box(node.as_ptr()),
                black_box(c"80".as_ptr()),
                black_box(hints),
                black_box(&mut result),
            )
        };
        assert_eq!(rc, 0, "hosts-backed getaddrinfo failed");
        assert!(
            !result.is_null(),
            "hosts-backed getaddrinfo returned no result"
        );
        accumulator = accumulator.rotate_left(7) ^ consume_addrinfo(result);
        unsafe { black_box(freeaddrinfo)(result) };
    }
    black_box(accumulator)
}

fn time_getaddrinfo_hosts_batch(
    getaddrinfo: GetaddrinfoFn,
    freeaddrinfo: FreeaddrinfoFn,
    hints: &libc::addrinfo,
    node: &CStr,
) -> f64 {
    let started = Instant::now();
    black_box(run_getaddrinfo_hosts_batch(
        getaddrinfo,
        freeaddrinfo,
        hints,
        node,
    ));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / GETADDRINFO_HOSTS_REPS as f64
}

fn measure_getaddrinfo_hosts_case(
    host_getaddrinfo: GetaddrinfoFn,
    host_freeaddrinfo: FreeaddrinfoFn,
    fl_getaddrinfo: GetaddrinfoFn,
    fl_freeaddrinfo: FreeaddrinfoFn,
    hints: &libc::addrinfo,
    node: &CStr,
) -> CaseResult {
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
                    fa = time_getaddrinfo_hosts_batch(fl_getaddrinfo, fl_freeaddrinfo, hints, node);
                    fb = time_getaddrinfo_hosts_batch(fl_getaddrinfo, fl_freeaddrinfo, hints, node);
                }
                0 => {
                    fb = time_getaddrinfo_hosts_batch(fl_getaddrinfo, fl_freeaddrinfo, hints, node);
                    fa = time_getaddrinfo_hosts_batch(fl_getaddrinfo, fl_freeaddrinfo, hints, node);
                }
                1 if sample % 2 == 0 => {
                    ga = time_getaddrinfo_hosts_batch(
                        host_getaddrinfo,
                        host_freeaddrinfo,
                        hints,
                        node,
                    );
                    gb = time_getaddrinfo_hosts_batch(
                        host_getaddrinfo,
                        host_freeaddrinfo,
                        hints,
                        node,
                    );
                }
                1 => {
                    gb = time_getaddrinfo_hosts_batch(
                        host_getaddrinfo,
                        host_freeaddrinfo,
                        hints,
                        node,
                    );
                    ga = time_getaddrinfo_hosts_batch(
                        host_getaddrinfo,
                        host_freeaddrinfo,
                        hints,
                        node,
                    );
                }
                2 if sample % 2 == 0 => {
                    effect_fl =
                        time_getaddrinfo_hosts_batch(fl_getaddrinfo, fl_freeaddrinfo, hints, node);
                    effect_glibc = time_getaddrinfo_hosts_batch(
                        host_getaddrinfo,
                        host_freeaddrinfo,
                        hints,
                        node,
                    );
                }
                2 => {
                    effect_glibc = time_getaddrinfo_hosts_batch(
                        host_getaddrinfo,
                        host_freeaddrinfo,
                        hints,
                        node,
                    );
                    effect_fl =
                        time_getaddrinfo_hosts_batch(fl_getaddrinfo, fl_freeaddrinfo, hints, node);
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

    summarize_case(
        "host_identity_ipv4_stream",
        "resolve this host's IPv4 stream service 80 through the hosts database",
        GETADDRINFO_HOSTS_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

fn consume_hostent(result: *mut libc::hostent) -> u64 {
    assert!(!result.is_null(), "gethostbyaddr returned a null hostent");
    let hostent = unsafe { &*result };
    assert!(
        !hostent.h_name.is_null(),
        "gethostbyaddr returned a null canonical name"
    );
    let name = unsafe { CStr::from_ptr(hostent.h_name) }.to_bytes();
    let mut accumulator = 0xcbf2_9ce4_8422_2325u64;
    accumulator ^= name.len() as u64;
    accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    accumulator ^= u64::from(name.first().copied().unwrap_or_default());
    accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    accumulator ^= hostent.h_addrtype as u64;
    accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    accumulator ^= hostent.h_length as u64;
    accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    if !hostent.h_addr_list.is_null() {
        let address = unsafe { *hostent.h_addr_list };
        if !address.is_null() && hostent.h_length > 0 {
            accumulator ^= u64::from(unsafe { *address.cast::<u8>() });
            accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    black_box(accumulator)
}

#[inline(never)]
fn run_gethostbyaddr_batch(gethostbyaddr: GethostbyaddrFn) -> u64 {
    let mut accumulator = 0u64;
    for _ in 0..GETHOSTBYADDR_REPS {
        let result = unsafe {
            black_box(gethostbyaddr)(
                black_box(IPV4_LOOPBACK.as_ptr().cast::<c_void>()),
                black_box(IPV4_LOOPBACK.len() as libc::socklen_t),
                black_box(libc::AF_INET),
            )
        };
        accumulator = accumulator.rotate_left(7) ^ consume_hostent(result);
    }
    black_box(accumulator)
}

fn time_gethostbyaddr_batch(gethostbyaddr: GethostbyaddrFn) -> f64 {
    let started = Instant::now();
    black_box(run_gethostbyaddr_batch(gethostbyaddr));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / GETHOSTBYADDR_REPS as f64
}

fn measure_gethostbyaddr_case(
    host_gethostbyaddr: GethostbyaddrFn,
    fl_gethostbyaddr: GethostbyaddrFn,
) -> CaseResult {
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
                    fa = time_gethostbyaddr_batch(fl_gethostbyaddr);
                    fb = time_gethostbyaddr_batch(fl_gethostbyaddr);
                }
                0 => {
                    fb = time_gethostbyaddr_batch(fl_gethostbyaddr);
                    fa = time_gethostbyaddr_batch(fl_gethostbyaddr);
                }
                1 if sample % 2 == 0 => {
                    ga = time_gethostbyaddr_batch(host_gethostbyaddr);
                    gb = time_gethostbyaddr_batch(host_gethostbyaddr);
                }
                1 => {
                    gb = time_gethostbyaddr_batch(host_gethostbyaddr);
                    ga = time_gethostbyaddr_batch(host_gethostbyaddr);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_gethostbyaddr_batch(fl_gethostbyaddr);
                    effect_glibc = time_gethostbyaddr_batch(host_gethostbyaddr);
                }
                2 => {
                    effect_glibc = time_gethostbyaddr_batch(host_gethostbyaddr);
                    effect_fl = time_gethostbyaddr_batch(fl_gethostbyaddr);
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

    summarize_case(
        "loopback_ipv4_hosts_reverse",
        "resolve IPv4 loopback to its canonical host entry through the hosts database",
        GETHOSTBYADDR_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_gethostbyname_batch(gethostbyname: GethostbynameFn, name: &CStr) -> u64 {
    let mut accumulator = 0u64;
    for _ in 0..GETHOSTBYNAME_REPS {
        let result = unsafe { black_box(gethostbyname)(black_box(name.as_ptr())) };
        accumulator = accumulator.rotate_left(7) ^ consume_hostent(result);
    }
    black_box(accumulator)
}

fn time_gethostbyname_batch(gethostbyname: GethostbynameFn, name: &CStr) -> f64 {
    let started = Instant::now();
    black_box(run_gethostbyname_batch(gethostbyname, name));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / GETHOSTBYNAME_REPS as f64
}

fn measure_gethostbyname_case(
    host_gethostbyname: GethostbynameFn,
    fl_gethostbyname: GethostbynameFn,
    name: &CStr,
) -> CaseResult {
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
                    fa = time_gethostbyname_batch(fl_gethostbyname, name);
                    fb = time_gethostbyname_batch(fl_gethostbyname, name);
                }
                0 => {
                    fb = time_gethostbyname_batch(fl_gethostbyname, name);
                    fa = time_gethostbyname_batch(fl_gethostbyname, name);
                }
                1 if sample % 2 == 0 => {
                    ga = time_gethostbyname_batch(host_gethostbyname, name);
                    gb = time_gethostbyname_batch(host_gethostbyname, name);
                }
                1 => {
                    gb = time_gethostbyname_batch(host_gethostbyname, name);
                    ga = time_gethostbyname_batch(host_gethostbyname, name);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_gethostbyname_batch(fl_gethostbyname, name);
                    effect_glibc = time_gethostbyname_batch(host_gethostbyname, name);
                }
                2 => {
                    effect_glibc = time_gethostbyname_batch(host_gethostbyname, name);
                    effect_fl = time_gethostbyname_batch(fl_gethostbyname, name);
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

    summarize_case(
        "localhost_ipv4_hosts_lookup",
        "resolve localhost to its canonical IPv4 host entry through the hosts database",
        GETHOSTBYNAME_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

#[inline(never)]
fn run_f32_unary_batch(function: F32UnaryFn) -> u64 {
    let mut accumulator = 0xcbf2_9ce4_8422_2325u64;
    for index in 0..F32_HYPERBOLIC_REPS {
        let input = HYPERBOLIC_MID_INPUTS[index & (HYPERBOLIC_MID_INPUTS.len() - 1)];
        let output = unsafe { black_box(function)(black_box(input)) };
        accumulator ^= u64::from(black_box(output).to_bits());
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    }
    black_box(accumulator)
}

fn time_f32_unary_batch(function: F32UnaryFn) -> f64 {
    let started = Instant::now();
    black_box(run_f32_unary_batch(function));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / F32_HYPERBOLIC_REPS as f64
}

fn measure_f32_unary_case(
    label: &'static str,
    note: &'static str,
    host: F32UnaryFn,
    fl: F32UnaryFn,
) -> CaseResult {
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
                    fa = time_f32_unary_batch(fl);
                    fb = time_f32_unary_batch(fl);
                }
                0 => {
                    fb = time_f32_unary_batch(fl);
                    fa = time_f32_unary_batch(fl);
                }
                1 if sample % 2 == 0 => {
                    ga = time_f32_unary_batch(host);
                    gb = time_f32_unary_batch(host);
                }
                1 => {
                    gb = time_f32_unary_batch(host);
                    ga = time_f32_unary_batch(host);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_f32_unary_batch(fl);
                    effect_glibc = time_f32_unary_batch(host);
                }
                2 => {
                    effect_glibc = time_f32_unary_batch(host);
                    effect_fl = time_f32_unary_batch(fl);
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

    summarize_case(
        label,
        note,
        F32_HYPERBOLIC_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

fn run_nl_langinfo(config: &Config) {
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
        result.print(
            "nl_langinfo",
            &incumbent_identity.path,
            threads_pre,
            threads_post,
        );
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

fn run_getrandom(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_symbol = unsafe { libc::dlsym(handle, c"getrandom".as_ptr()) };
    assert!(
        !fl_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC getrandom")
    );

    let host: GetrandomFn = linked_host_getrandom;
    let fl: GetrandomFn = unsafe { std::mem::transmute(fl_symbol) };
    let incumbent_identity =
        symbol_object(host as *const () as *const c_void).expect("identify host getrandom object");
    let fl_identity =
        symbol_object(fl_symbol.cast_const()).expect("identify FrankenLibC getrandom object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=getrandom");
    println!("FL_LINKAGE explicit_dlopen_local symbol=getrandom");
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
        "ARM_DISTINCT symbol=getrandom incumbent_address={:#x} fl_address={:#x}",
        host as usize, fl as usize,
    );

    let mut conformance_comparisons = 0usize;
    for case in GETRANDOM_CASES {
        let mut host_buffer = [0xa5u8; 256];
        let mut fl_buffer = [0xa5u8; 256];
        let host_result = unsafe { host(host_buffer.as_mut_ptr().cast(), case.length, case.flags) };
        let fl_result = unsafe { fl(fl_buffer.as_mut_ptr().cast(), case.length, case.flags) };
        assert_eq!(
            host_result, case.length as isize,
            "host getrandom contract mismatch for {}",
            case.label
        );
        assert_eq!(
            fl_result, host_result,
            "FrankenLibC getrandom contract mismatch for {}",
            case.label
        );
        if case.length == 0 {
            assert_eq!(
                host_buffer[0], 0xa5,
                "host getrandom zero-length request wrote output"
            );
            assert_eq!(
                fl_buffer[0], 0xa5,
                "FrankenLibC getrandom zero-length request wrote output"
            );
        } else if case.length > 4 {
            assert!(
                host_buffer[..case.length].iter().any(|byte| *byte != 0xa5),
                "host getrandom did not visibly fill {}",
                case.label
            );
            assert!(
                fl_buffer[..case.length].iter().any(|byte| *byte != 0xa5),
                "FrankenLibC getrandom did not visibly fill {}",
                case.label
            );
        }
        conformance_comparisons += 1;
    }
    let mut host_nonblock = [0u8; 32];
    let mut fl_nonblock = [0u8; 32];
    let host_nonblock_result = unsafe {
        host(
            host_nonblock.as_mut_ptr().cast(),
            host_nonblock.len(),
            libc::GRND_NONBLOCK,
        )
    };
    let fl_nonblock_result = unsafe {
        fl(
            fl_nonblock.as_mut_ptr().cast(),
            fl_nonblock.len(),
            libc::GRND_NONBLOCK,
        )
    };
    assert_eq!(
        host_nonblock_result, 32,
        "host getrandom GRND_NONBLOCK request failed"
    );
    assert_eq!(
        fl_nonblock_result, host_nonblock_result,
        "FrankenLibC getrandom GRND_NONBLOCK contract mismatch"
    );
    conformance_comparisons += 1;
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=getrandom \
         successful_lengths=0,1,32,256 flags=0,GRND_NONBLOCK \
         comparisons={conformance_comparisons} verdict=pass \
         random_payload_equality_required=false"
    );
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=getrandom verdict=pass");
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
        "getrandom benchmark requires one actually observed process thread"
    );

    let results = GETRANDOM_CASES
        .iter()
        .map(|case| measure_getrandom_case(host, fl, case))
        .collect::<Vec<_>>();

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, 1,
        "getrandom benchmark requires one actually observed process thread"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));

    for result in &results {
        result.print(
            "getrandom",
            &incumbent_identity.path,
            threads_pre,
            threads_post,
        );
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
        .find(|result| result.label == "thirty_two_bytes")
        .expect("missing thirty_two_bytes result");
    let verdict = if results.iter().all(CaseResult::decidable) {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=getrandom verdict={verdict} \
         cases={} wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=thirty_two_bytes headline_ratio_median={:.6} \
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

fn run_getauxval(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_symbol = unsafe { libc::dlsym(handle, c"getauxval".as_ptr()) };
    assert!(
        !fl_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC getauxval")
    );
    let fl_errno_symbol = unsafe { libc::dlsym(handle, c"__errno_location".as_ptr()) };
    assert!(
        !fl_errno_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC __errno_location")
    );

    let host: GetauxvalFn = linked_host_getauxval;
    let fl: GetauxvalFn = unsafe { std::mem::transmute(fl_symbol) };
    let host_errno: ErrnoLocationFn = linked_host_errno_location;
    let fl_errno: ErrnoLocationFn = unsafe { std::mem::transmute(fl_errno_symbol) };
    let incumbent_identity =
        symbol_object(host as *const () as *const c_void).expect("identify host getauxval object");
    let fl_identity =
        symbol_object(fl_symbol.cast_const()).expect("identify FrankenLibC getauxval object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=getauxval");
    println!("FL_LINKAGE explicit_dlopen_local symbol=getauxval");
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
        "ARM_DISTINCT symbol=getauxval incumbent_address={:#x} fl_address={:#x}",
        host as usize, fl as usize,
    );

    let conformance_types = [
        (libc::AT_PHDR as c_ulong, "AT_PHDR"),
        (libc::AT_PHENT as c_ulong, "AT_PHENT"),
        (libc::AT_PHNUM as c_ulong, "AT_PHNUM"),
        (libc::AT_PAGESZ as c_ulong, "AT_PAGESZ"),
        (libc::AT_BASE as c_ulong, "AT_BASE"),
        (libc::AT_ENTRY as c_ulong, "AT_ENTRY"),
        (libc::AT_UID as c_ulong, "AT_UID"),
        (libc::AT_EUID as c_ulong, "AT_EUID"),
        (libc::AT_GID as c_ulong, "AT_GID"),
        (libc::AT_EGID as c_ulong, "AT_EGID"),
        (libc::AT_CLKTCK as c_ulong, "AT_CLKTCK"),
        (libc::AT_SECURE as c_ulong, "AT_SECURE"),
        (libc::AT_RANDOM as c_ulong, "AT_RANDOM"),
        (libc::AT_HWCAP2 as c_ulong, "AT_HWCAP2"),
        (libc::AT_EXECFN as c_ulong, "AT_EXECFN"),
        (libc::AT_SYSINFO_EHDR as c_ulong, "AT_SYSINFO_EHDR"),
        (63, "AT_MISSING_CACHED"),
        (9_999, "AT_MISSING_UNCACHED"),
    ];
    for (type_, name) in conformance_types {
        unsafe { *host_errno() = libc::EBUSY };
        let host_value = unsafe { host(type_) };
        let host_errno_after = unsafe { *host_errno() };
        unsafe { *fl_errno() = libc::EBUSY };
        let fl_value = unsafe { fl(type_) };
        let fl_errno_after = unsafe { *fl_errno() };
        assert_eq!(
            fl_value, host_value,
            "getauxval value mismatch for {name} ({type_})"
        );
        assert_eq!(
            fl_errno_after, host_errno_after,
            "getauxval errno mismatch for {name} ({type_})"
        );
    }
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=getauxval comparisons={} \
         value_and_errno_verdict=pass at_hwcap_excluded=true \
         at_hwcap_reason=glibc_startup_masking",
        conformance_types.len(),
    );
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=getauxval verdict=pass");
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
        "getauxval benchmark requires one actually observed process thread"
    );

    let results = GETAUXVAL_CASES
        .iter()
        .map(|case| measure_getauxval_case(host, fl, case))
        .collect::<Vec<_>>();

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, 1,
        "getauxval benchmark requires one actually observed process thread"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));

    for result in &results {
        result.print(
            "getauxval",
            &incumbent_identity.path,
            threads_pre,
            threads_post,
        );
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
        .find(|result| result.label == "pagesz")
        .expect("missing pagesz result");
    let verdict = if results.iter().all(CaseResult::decidable) {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=getauxval verdict={verdict} \
         cases={} wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=pagesz headline_ratio_median={:.6} \
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

fn run_sem_post(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));

    let fl_init_symbol = unsafe { libc::dlsym(handle, c"sem_init".as_ptr()) };
    assert!(
        !fl_init_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC sem_init")
    );
    let fl_destroy_symbol = unsafe { libc::dlsym(handle, c"sem_destroy".as_ptr()) };
    assert!(
        !fl_destroy_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC sem_destroy")
    );
    let fl_post_symbol = unsafe { libc::dlsym(handle, c"sem_post".as_ptr()) };
    assert!(
        !fl_post_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC sem_post")
    );
    let fl_trywait_symbol = unsafe { libc::dlsym(handle, c"sem_trywait".as_ptr()) };
    assert!(
        !fl_trywait_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC sem_trywait")
    );
    let fl_errno_symbol = unsafe { libc::dlsym(handle, c"__errno_location".as_ptr()) };
    assert!(
        !fl_errno_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC __errno_location")
    );

    let host_init: SemInitFn = linked_host_sem_init;
    let host_destroy: SemDestroyFn = linked_host_sem_destroy;
    let host_post: SemPostFn = linked_host_sem_post;
    let host_trywait: SemTrywaitFn = linked_host_sem_trywait;
    let host_errno: ErrnoLocationFn = linked_host_errno_location;
    let fl_init: SemInitFn = unsafe { std::mem::transmute(fl_init_symbol) };
    let fl_destroy: SemDestroyFn = unsafe { std::mem::transmute(fl_destroy_symbol) };
    let fl_post: SemPostFn = unsafe { std::mem::transmute(fl_post_symbol) };
    let fl_trywait: SemTrywaitFn = unsafe { std::mem::transmute(fl_trywait_symbol) };
    let fl_errno: ErrnoLocationFn = unsafe { std::mem::transmute(fl_errno_symbol) };

    let incumbent_identity = symbol_object(host_post as *const () as *const c_void)
        .expect("identify host sem_post object");
    let fl_identity =
        symbol_object(fl_post_symbol.cast_const()).expect("identify FrankenLibC sem_post object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=sem_post");
    println!("FL_LINKAGE explicit_dlopen_local symbol=sem_post");
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
        host_post as usize, fl_post as usize,
        "both arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=sem_post incumbent_address={:#x} fl_address={:#x}",
        host_post as usize, fl_post as usize,
    );

    let mut host_sem: libc::sem_t = unsafe { std::mem::zeroed() };
    let mut fl_sem: libc::sem_t = unsafe { std::mem::zeroed() };
    let host_sem_ptr = &mut host_sem;
    let fl_sem_ptr = &mut fl_sem;
    assert_eq!(
        unsafe { host_init(host_sem_ptr, 0, 0) },
        0,
        "host sem_init failed"
    );
    assert_eq!(
        unsafe { fl_init(fl_sem_ptr, 0, 0) },
        0,
        "FrankenLibC sem_init failed"
    );

    unsafe { *host_errno() = libc::EBUSY };
    let host_empty_result = unsafe { host_trywait(host_sem_ptr) };
    let host_empty_errno = unsafe { *host_errno() };
    unsafe { *fl_errno() = libc::EBUSY };
    let fl_empty_result = unsafe { fl_trywait(fl_sem_ptr) };
    let fl_empty_errno = unsafe { *fl_errno() };
    assert_eq!(
        (fl_empty_result, fl_empty_errno),
        (host_empty_result, host_empty_errno),
        "empty sem_trywait result or errno diverged"
    );
    assert_eq!(
        (host_empty_result, host_empty_errno),
        (-1, libc::EAGAIN),
        "host empty sem_trywait contract changed"
    );

    for cycle in 0..4 {
        unsafe { *host_errno() = libc::EBUSY };
        let host_post_result = unsafe { host_post(host_sem_ptr) };
        let host_post_errno = unsafe { *host_errno() };
        unsafe { *fl_errno() = libc::EBUSY };
        let fl_post_result = unsafe { fl_post(fl_sem_ptr) };
        let fl_post_errno = unsafe { *fl_errno() };
        assert_eq!(
            (fl_post_result, fl_post_errno),
            (host_post_result, host_post_errno),
            "sem_post result or errno diverged in conformance cycle {cycle}"
        );

        unsafe { *host_errno() = libc::EBUSY };
        let host_trywait_result = unsafe { host_trywait(host_sem_ptr) };
        let host_trywait_errno = unsafe { *host_errno() };
        unsafe { *fl_errno() = libc::EBUSY };
        let fl_trywait_result = unsafe { fl_trywait(fl_sem_ptr) };
        let fl_trywait_errno = unsafe { *fl_errno() };
        assert_eq!(
            (fl_trywait_result, fl_trywait_errno),
            (host_trywait_result, host_trywait_errno),
            "successful sem_trywait result or errno diverged in conformance cycle {cycle}"
        );
        assert_eq!(
            (host_post_result, host_trywait_result),
            (0, 0),
            "host semaphore cycle failed in conformance cycle {cycle}"
        );
    }
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=sem_post comparisons=18 \
         result_and_errno_verdict=pass pshared=0 initial_value=0"
    );

    if config.verify_only {
        assert_eq!(
            unsafe { host_destroy(host_sem_ptr) },
            0,
            "host sem_destroy failed"
        );
        assert_eq!(
            unsafe { fl_destroy(fl_sem_ptr) },
            0,
            "FrankenLibC sem_destroy failed"
        );
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=sem_post verdict=pass");
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
        "sem_post benchmark requires one actually observed process thread"
    );

    let result = measure_sem_post_case(
        host_post,
        host_trywait,
        host_sem_ptr,
        fl_post,
        fl_trywait,
        fl_sem_ptr,
    );

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, 1,
        "sem_post benchmark requires one actually observed process thread"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    result.print(
        "sem_post",
        &incumbent_identity.path,
        threads_pre,
        threads_post,
    );

    let wins = usize::from(result.comparison == "FL_FASTER");
    let losses = usize::from(result.comparison == "FL_SLOWER");
    let undecidable = 1 - wins - losses;
    let verdict = if result.decidable() {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=sem_post verdict={verdict} \
         cases=1 wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=uncontended_cycle headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        result.effect_median, result.comparison,
    );

    assert_eq!(
        unsafe { host_destroy(host_sem_ptr) },
        0,
        "host sem_destroy failed"
    );
    assert_eq!(
        unsafe { fl_destroy(fl_sem_ptr) },
        0,
        "FrankenLibC sem_destroy failed"
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

fn run_thrd_current(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_symbol = unsafe { libc::dlsym(handle, c"thrd_current".as_ptr()) };
    assert!(
        !fl_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC thrd_current")
    );

    let host: ThrdCurrentFn = linked_host_thrd_current;
    let fl: ThrdCurrentFn = unsafe { std::mem::transmute(fl_symbol) };
    let incumbent_identity = symbol_object(host as *const () as *const c_void)
        .expect("identify host thrd_current object");
    let fl_identity =
        symbol_object(fl_symbol.cast_const()).expect("identify FrankenLibC thrd_current object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=thrd_current");
    println!("FL_LINKAGE explicit_dlopen_local symbol=thrd_current");
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
        "ARM_DISTINCT symbol=thrd_current incumbent_address={:#x} fl_address={:#x}",
        host as usize, fl as usize,
    );

    let host_main_first = unsafe { host() };
    let host_main_second = unsafe { host() };
    let fl_main_first = unsafe { fl() };
    let fl_main_second = unsafe { fl() };
    assert_ne!(host_main_first, 0, "host main-thread token is zero");
    assert_ne!(fl_main_first, 0, "FrankenLibC main-thread token is zero");
    assert_eq!(
        host_main_first, host_main_second,
        "host main-thread token is unstable"
    );
    assert_eq!(
        fl_main_first, fl_main_second,
        "FrankenLibC main-thread token is unstable"
    );

    let child = std::thread::spawn(move || {
        let host_first = unsafe { host() };
        let host_second = unsafe { host() };
        let fl_first = unsafe { fl() };
        let fl_second = unsafe { fl() };
        (host_first, host_second, fl_first, fl_second)
    })
    .join()
    .expect("thrd_current conformance child panicked");
    assert_ne!(child.0, 0, "host child-thread token is zero");
    assert_ne!(child.2, 0, "FrankenLibC child-thread token is zero");
    assert_eq!(child.0, child.1, "host child-thread token is unstable");
    assert_eq!(
        child.2, child.3,
        "FrankenLibC child-thread token is unstable"
    );
    assert_ne!(
        child.0, host_main_first,
        "host main and child thread tokens are equal"
    );
    assert_ne!(
        child.2, fl_main_first,
        "FrankenLibC main and child thread tokens are equal"
    );
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=thrd_current comparisons=8 \
         stable_nonzero_per_thread_identity_verdict=pass opaque_cross_provider_tokens=true"
    );
    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbol=thrd_current phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=thrd_current verdict=pass");
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
        threads_pre, threads_pre_guard,
        "thrd_current observed thread count changed between conformance and measurement"
    );

    let result = measure_thrd_current_case(host, fl);

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "thrd_current observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    result.print(
        "thrd_current",
        &incumbent_identity.path,
        threads_pre,
        threads_post,
    );

    let wins = usize::from(result.comparison == "FL_FASTER");
    let losses = usize::from(result.comparison == "FL_SLOWER");
    let undecidable = 1 - wins - losses;
    let verdict = if result.decidable() {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=thrd_current verdict={verdict} \
         cases=1 wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=current_identity headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        result.effect_median, result.comparison,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

fn verify_mtx_provider(
    provider: &str,
    init: MtxInitFn,
    trylock: MtxTrylockFn,
    unlock: MtxUnlockFn,
    destroy: MtxDestroyFn,
) {
    let mut mutex: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
    let mutex_ptr = &mut mutex;
    assert_eq!(
        unsafe { init(mutex_ptr, 0) },
        0,
        "{provider} mtx_init(mtx_plain) failed"
    );
    assert_eq!(
        unsafe { trylock(mutex_ptr) },
        0,
        "{provider} first mtx_trylock did not acquire the mutex"
    );
    assert_eq!(
        unsafe { trylock(mutex_ptr) },
        1,
        "{provider} already-owned mtx_trylock did not return thrd_busy"
    );
    assert_eq!(
        unsafe { unlock(mutex_ptr) },
        0,
        "{provider} mtx_unlock failed"
    );
    unsafe { destroy(mutex_ptr) };
}

fn run_mtx_trylock(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_init_symbol = unsafe { libc::dlsym(handle, c"mtx_init".as_ptr()) };
    assert!(
        !fl_init_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC mtx_init")
    );
    let fl_trylock_symbol = unsafe { libc::dlsym(handle, c"mtx_trylock".as_ptr()) };
    assert!(
        !fl_trylock_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC mtx_trylock")
    );
    let fl_unlock_symbol = unsafe { libc::dlsym(handle, c"mtx_unlock".as_ptr()) };
    assert!(
        !fl_unlock_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC mtx_unlock")
    );
    let fl_destroy_symbol = unsafe { libc::dlsym(handle, c"mtx_destroy".as_ptr()) };
    assert!(
        !fl_destroy_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC mtx_destroy")
    );

    let host_init: MtxInitFn = linked_host_mtx_init;
    let host_trylock: MtxTrylockFn = linked_host_mtx_trylock;
    let host_unlock: MtxUnlockFn = linked_host_mtx_unlock;
    let host_destroy: MtxDestroyFn = linked_host_mtx_destroy;
    let fl_init: MtxInitFn = unsafe { std::mem::transmute(fl_init_symbol) };
    let fl_trylock: MtxTrylockFn = unsafe { std::mem::transmute(fl_trylock_symbol) };
    let fl_unlock: MtxUnlockFn = unsafe { std::mem::transmute(fl_unlock_symbol) };
    let fl_destroy: MtxDestroyFn = unsafe { std::mem::transmute(fl_destroy_symbol) };

    let incumbent_identity = symbol_object(host_trylock as *const () as *const c_void)
        .expect("identify host mtx_trylock object");
    let fl_identity = symbol_object(fl_trylock_symbol.cast_const())
        .expect("identify FrankenLibC mtx_trylock object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=mtx_trylock");
    println!("FL_LINKAGE explicit_dlopen_local symbol=mtx_trylock");
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
        host_trylock as usize, fl_trylock as usize,
        "both arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=mtx_trylock incumbent_address={:#x} fl_address={:#x}",
        host_trylock as usize, fl_trylock as usize,
    );

    verify_mtx_provider("host", host_init, host_trylock, host_unlock, host_destroy);
    verify_mtx_provider("FrankenLibC", fl_init, fl_trylock, fl_unlock, fl_destroy);
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=mtx_trylock comparisons=8 \
         plain_init_first_lock_busy_unlock_verdict=pass"
    );
    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbol=mtx_trylock phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=mtx_trylock verdict=pass");
        return;
    }

    let mut host_mutex: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
    let mut fl_mutex: libc::pthread_mutex_t = unsafe { std::mem::zeroed() };
    let host_mutex_ptr = &mut host_mutex;
    let fl_mutex_ptr = &mut fl_mutex;
    assert_eq!(
        unsafe { host_init(host_mutex_ptr, 0) },
        0,
        "host benchmark mtx_init failed"
    );
    assert_eq!(
        unsafe { fl_init(fl_mutex_ptr, 0) },
        0,
        "FrankenLibC benchmark mtx_init failed"
    );
    assert_eq!(
        unsafe { host_trylock(host_mutex_ptr) },
        0,
        "host benchmark mutex setup lock failed"
    );
    assert_eq!(
        unsafe { fl_trylock(fl_mutex_ptr) },
        0,
        "FrankenLibC benchmark mutex setup lock failed"
    );

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
        threads_pre, threads_pre_guard,
        "mtx_trylock observed thread count changed between conformance and measurement"
    );

    let result = measure_mtx_trylock_case(host_trylock, fl_trylock, host_mutex_ptr, fl_mutex_ptr);

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "mtx_trylock observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    result.print(
        "mtx_trylock",
        &incumbent_identity.path,
        threads_pre,
        threads_post,
    );

    assert_eq!(
        unsafe { host_unlock(host_mutex_ptr) },
        0,
        "host benchmark mtx_unlock failed"
    );
    assert_eq!(
        unsafe { fl_unlock(fl_mutex_ptr) },
        0,
        "FrankenLibC benchmark mtx_unlock failed"
    );
    unsafe { host_destroy(host_mutex_ptr) };
    unsafe { fl_destroy(fl_mutex_ptr) };

    let wins = usize::from(result.comparison == "FL_FASTER");
    let losses = usize::from(result.comparison == "FL_SLOWER");
    let undecidable = 1 - wins - losses;
    let verdict = if result.decidable() {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=mtx_trylock verdict={verdict} \
         cases=1 wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=already_owned_busy headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        result.effect_median, result.comparison,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct AddrinfoObservation {
    family: c_int,
    socktype: c_int,
    protocol: c_int,
    address: u32,
    port: u16,
}

fn observe_addrinfo(mut result: *mut libc::addrinfo) -> Vec<AddrinfoObservation> {
    let mut observations = Vec::new();
    while !result.is_null() {
        let current = unsafe { &*result };
        assert_eq!(
            current.ai_family,
            libc::AF_INET,
            "hosts-backed getaddrinfo returned a non-IPv4 row"
        );
        assert!(
            !current.ai_addr.is_null(),
            "hosts-backed getaddrinfo returned a null address"
        );
        assert!(
            current.ai_addrlen as usize >= std::mem::size_of::<libc::sockaddr_in>(),
            "hosts-backed getaddrinfo returned a short IPv4 address"
        );
        let address = unsafe { &*current.ai_addr.cast::<libc::sockaddr_in>() };
        observations.push(AddrinfoObservation {
            family: current.ai_family,
            socktype: current.ai_socktype,
            protocol: current.ai_protocol,
            address: u32::from_be(address.sin_addr.s_addr),
            port: u16::from_be(address.sin_port),
        });
        result = current.ai_next;
    }
    observations.sort();
    observations
}

fn call_getaddrinfo_once(
    getaddrinfo: GetaddrinfoFn,
    freeaddrinfo: FreeaddrinfoFn,
    hints: &libc::addrinfo,
    node: &CStr,
) -> Vec<AddrinfoObservation> {
    let mut result = std::ptr::null_mut();
    let rc = unsafe { getaddrinfo(node.as_ptr(), c"80".as_ptr(), hints, &mut result) };
    assert_eq!(rc, 0, "hosts-backed getaddrinfo conformance call failed");
    assert!(
        !result.is_null(),
        "hosts-backed getaddrinfo conformance call returned no result"
    );
    let observations = observe_addrinfo(result);
    unsafe { freeaddrinfo(result) };
    observations
}

fn run_getaddrinfo_hosts(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_getaddrinfo_symbol = unsafe { libc::dlsym(handle, c"getaddrinfo".as_ptr()) };
    assert!(
        !fl_getaddrinfo_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC getaddrinfo")
    );
    let fl_freeaddrinfo_symbol = unsafe { libc::dlsym(handle, c"freeaddrinfo".as_ptr()) };
    assert!(
        !fl_freeaddrinfo_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC freeaddrinfo")
    );

    let host_getaddrinfo: GetaddrinfoFn = linked_host_getaddrinfo;
    let host_freeaddrinfo: FreeaddrinfoFn = linked_host_freeaddrinfo;
    let fl_getaddrinfo: GetaddrinfoFn = unsafe { std::mem::transmute(fl_getaddrinfo_symbol) };
    let fl_freeaddrinfo: FreeaddrinfoFn = unsafe { std::mem::transmute(fl_freeaddrinfo_symbol) };
    let incumbent_identity = symbol_object(host_getaddrinfo as *const () as *const c_void)
        .expect("identify host getaddrinfo object");
    let fl_identity = symbol_object(fl_getaddrinfo_symbol.cast_const())
        .expect("identify FrankenLibC getaddrinfo object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=getaddrinfo");
    println!("FL_LINKAGE explicit_dlopen_local symbol=getaddrinfo");
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
        host_getaddrinfo as usize, fl_getaddrinfo as usize,
        "both arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=getaddrinfo incumbent_address={:#x} fl_address={:#x}",
        host_getaddrinfo as usize, fl_getaddrinfo as usize,
    );

    let hints = hosts_getaddrinfo_hints();
    let host_name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("read host identity for hosts-backed getaddrinfo");
    let host_name =
        CString::new(host_name.trim()).expect("host identity contains an interior NUL byte");
    let incumbent_observations =
        call_getaddrinfo_once(host_getaddrinfo, host_freeaddrinfo, &hints, &host_name);
    let fl_observations =
        call_getaddrinfo_once(fl_getaddrinfo, fl_freeaddrinfo, &hints, &host_name);
    assert_eq!(
        fl_observations, incumbent_observations,
        "hosts-backed getaddrinfo semantic results differ"
    );
    assert!(
        !fl_observations.is_empty(),
        "hosts-backed getaddrinfo conformance produced no rows"
    );
    assert!(
        fl_observations
            .iter()
            .all(|row| row.address != 0 && row.port == 80),
        "host-identity lookup returned an invalid address or service port"
    );
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=getaddrinfo comparisons={} \
         host_identity={} host_identity_ipv4_stream_rows={} \
         exact_semantic_result_verdict=pass",
        fl_observations.len() * 5,
        host_name.to_string_lossy(),
        fl_observations.len(),
    );
    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbol=getaddrinfo phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=getaddrinfo verdict=pass");
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
        threads_pre, threads_pre_guard,
        "getaddrinfo observed thread count changed between conformance and measurement"
    );

    let result = measure_getaddrinfo_hosts_case(
        host_getaddrinfo,
        host_freeaddrinfo,
        fl_getaddrinfo,
        fl_freeaddrinfo,
        &hints,
        &host_name,
    );

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "getaddrinfo observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    result.print(
        "getaddrinfo",
        &incumbent_identity.path,
        threads_pre,
        threads_post,
    );

    let wins = usize::from(result.comparison == "FL_FASTER");
    let losses = usize::from(result.comparison == "FL_SLOWER");
    let undecidable = 1 - wins - losses;
    let verdict = if result.decidable() {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=getaddrinfo verdict={verdict} \
         cases=1 wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=host_identity_ipv4_stream headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        result.effect_median, result.comparison,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostentObservation {
    name: Vec<u8>,
    aliases: Vec<Vec<u8>>,
    address_type: c_int,
    address_length: c_int,
    addresses: Vec<Vec<u8>>,
}

fn observe_hostent_strings(list: *mut *mut c_char, label: &str) -> Vec<Vec<u8>> {
    if list.is_null() {
        return Vec::new();
    }
    let mut values = Vec::new();
    for index in 0..64 {
        let value = unsafe { *list.add(index) };
        if value.is_null() {
            values.sort();
            return values;
        }
        values.push(unsafe { CStr::from_ptr(value) }.to_bytes().to_vec());
    }
    panic!("gethostbyaddr {label} list lacked a terminator within 64 entries");
}

fn observe_hostent_addresses(list: *mut *mut c_char, address_length: c_int) -> Vec<Vec<u8>> {
    assert!(
        address_length > 0 && address_length <= 16,
        "gethostbyaddr returned invalid address length {address_length}"
    );
    if list.is_null() {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    for index in 0..64 {
        let address = unsafe { *list.add(index) };
        if address.is_null() {
            addresses.sort();
            return addresses;
        }
        addresses.push(
            unsafe { std::slice::from_raw_parts(address.cast::<u8>(), address_length as usize) }
                .to_vec(),
        );
    }
    panic!("gethostbyaddr address list lacked a terminator within 64 entries");
}

fn observe_hostent(result: *mut libc::hostent) -> HostentObservation {
    assert!(
        !result.is_null(),
        "gethostbyaddr conformance call returned a null hostent"
    );
    let hostent = unsafe { &*result };
    assert!(
        !hostent.h_name.is_null(),
        "gethostbyaddr conformance call returned a null canonical name"
    );
    HostentObservation {
        name: unsafe { CStr::from_ptr(hostent.h_name) }
            .to_bytes()
            .to_vec(),
        aliases: observe_hostent_strings(hostent.h_aliases, "alias"),
        address_type: hostent.h_addrtype,
        address_length: hostent.h_length,
        addresses: observe_hostent_addresses(hostent.h_addr_list, hostent.h_length),
    }
}

fn call_gethostbyaddr_once(gethostbyaddr: GethostbyaddrFn) -> HostentObservation {
    let result = unsafe {
        gethostbyaddr(
            IPV4_LOOPBACK.as_ptr().cast::<c_void>(),
            IPV4_LOOPBACK.len() as libc::socklen_t,
            libc::AF_INET,
        )
    };
    observe_hostent(result)
}

fn run_gethostbyaddr(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_gethostbyaddr_symbol = unsafe { libc::dlsym(handle, c"gethostbyaddr".as_ptr()) };
    assert!(
        !fl_gethostbyaddr_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC gethostbyaddr")
    );

    let host_gethostbyaddr: GethostbyaddrFn = linked_host_gethostbyaddr;
    let fl_gethostbyaddr: GethostbyaddrFn = unsafe { std::mem::transmute(fl_gethostbyaddr_symbol) };
    let incumbent_identity = symbol_object(host_gethostbyaddr as *const () as *const c_void)
        .expect("identify host gethostbyaddr object");
    let fl_identity = symbol_object(fl_gethostbyaddr_symbol.cast_const())
        .expect("identify FrankenLibC gethostbyaddr object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=gethostbyaddr");
    println!("FL_LINKAGE explicit_dlopen_local symbol=gethostbyaddr");
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
        host_gethostbyaddr as usize, fl_gethostbyaddr as usize,
        "both arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=gethostbyaddr incumbent_address={:#x} fl_address={:#x}",
        host_gethostbyaddr as usize, fl_gethostbyaddr as usize,
    );

    let incumbent_observation = call_gethostbyaddr_once(host_gethostbyaddr);
    let fl_observation = call_gethostbyaddr_once(fl_gethostbyaddr);
    assert_eq!(
        fl_observation, incumbent_observation,
        "gethostbyaddr loopback semantic result differs from host glibc"
    );
    assert_eq!(
        fl_observation.address_type,
        libc::AF_INET,
        "gethostbyaddr loopback result is not IPv4"
    );
    assert_eq!(
        fl_observation.address_length,
        IPV4_LOOPBACK.len() as c_int,
        "gethostbyaddr loopback result has the wrong address length"
    );
    assert!(
        fl_observation
            .addresses
            .iter()
            .any(|address| address == &IPV4_LOOPBACK),
        "gethostbyaddr loopback result omitted the queried address"
    );
    for trial in 1..8 {
        assert_eq!(
            call_gethostbyaddr_once(host_gethostbyaddr),
            incumbent_observation,
            "host gethostbyaddr result changed on conformance trial {trial}"
        );
        assert_eq!(
            call_gethostbyaddr_once(fl_gethostbyaddr),
            fl_observation,
            "FrankenLibC gethostbyaddr result changed on conformance trial {trial}"
        );
    }
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=gethostbyaddr comparisons=16 \
         query_ipv4=127.0.0.1 canonical_name={} aliases={} addresses={} \
         exact_semantic_result_verdict=pass",
        String::from_utf8_lossy(&fl_observation.name),
        fl_observation.aliases.len(),
        fl_observation.addresses.len(),
    );

    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbol=gethostbyaddr phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=gethostbyaddr verdict=pass");
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
        threads_pre, threads_pre_guard,
        "gethostbyaddr observed thread count changed between conformance and measurement"
    );

    let result = measure_gethostbyaddr_case(host_gethostbyaddr, fl_gethostbyaddr);

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "gethostbyaddr observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    result.print(
        "gethostbyaddr",
        &incumbent_identity.path,
        threads_pre,
        threads_post,
    );

    let wins = usize::from(result.comparison == "FL_FASTER");
    let losses = usize::from(result.comparison == "FL_SLOWER");
    let undecidable = 1 - wins - losses;
    let verdict = if result.decidable() {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=gethostbyaddr verdict={verdict} \
         cases=1 wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=loopback_ipv4_hosts_reverse headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        result.effect_median, result.comparison,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

fn call_gethostbyname_once(gethostbyname: GethostbynameFn, name: &CStr) -> HostentObservation {
    let result = unsafe { gethostbyname(name.as_ptr()) };
    observe_hostent(result)
}

fn run_gethostbyname(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_gethostbyname_symbol = unsafe { libc::dlsym(handle, c"gethostbyname".as_ptr()) };
    assert!(
        !fl_gethostbyname_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC gethostbyname")
    );

    let host_gethostbyname: GethostbynameFn = linked_host_gethostbyname;
    let fl_gethostbyname: GethostbynameFn = unsafe { std::mem::transmute(fl_gethostbyname_symbol) };
    let incumbent_identity = symbol_object(host_gethostbyname as *const () as *const c_void)
        .expect("identify host gethostbyname object");
    let fl_identity = symbol_object(fl_gethostbyname_symbol.cast_const())
        .expect("identify FrankenLibC gethostbyname object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=gethostbyname");
    println!("FL_LINKAGE explicit_dlopen_local symbol=gethostbyname");
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
        host_gethostbyname as usize, fl_gethostbyname as usize,
        "both arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=gethostbyname incumbent_address={:#x} fl_address={:#x}",
        host_gethostbyname as usize, fl_gethostbyname as usize,
    );

    let query = c"localhost";
    let incumbent_observation = call_gethostbyname_once(host_gethostbyname, query);
    let fl_observation = call_gethostbyname_once(fl_gethostbyname, query);
    if fl_observation != incumbent_observation {
        let threads_observed = observed_threads();
        println!(
            "THREADS_OBSERVED symbol=gethostbyname phase=conformance count={threads_observed}"
        );
        eprintln!(
            "INCUMBENT_COVERAGE_BLOCKED phase=conformance symbol=gethostbyname \
             reason=hostent_mismatch threads_observed={threads_observed} \
             incumbent={incumbent_observation:?} fl={fl_observation:?}"
        );
        std::process::exit(2);
    }
    assert_eq!(
        fl_observation.address_type,
        libc::AF_INET,
        "gethostbyname localhost result is not IPv4"
    );
    assert_eq!(
        fl_observation.address_length,
        IPV4_LOOPBACK.len() as c_int,
        "gethostbyname localhost result has the wrong address length"
    );
    assert!(
        fl_observation
            .addresses
            .iter()
            .any(|address| address == &IPV4_LOOPBACK),
        "gethostbyname localhost result omitted IPv4 loopback"
    );
    for trial in 1..8 {
        assert_eq!(
            call_gethostbyname_once(host_gethostbyname, query),
            incumbent_observation,
            "host gethostbyname result changed on conformance trial {trial}"
        );
        assert_eq!(
            call_gethostbyname_once(fl_gethostbyname, query),
            fl_observation,
            "FrankenLibC gethostbyname result changed on conformance trial {trial}"
        );
    }
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=gethostbyname comparisons=16 \
         query=localhost canonical_name={} aliases={} addresses={} \
         exact_semantic_result_verdict=pass",
        String::from_utf8_lossy(&fl_observation.name),
        fl_observation.aliases.len(),
        fl_observation.addresses.len(),
    );

    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbol=gethostbyname phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=gethostbyname verdict=pass");
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
        threads_pre, threads_pre_guard,
        "gethostbyname observed thread count changed between conformance and measurement"
    );

    let result = measure_gethostbyname_case(host_gethostbyname, fl_gethostbyname, query);

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "gethostbyname observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    result.print(
        "gethostbyname",
        &incumbent_identity.path,
        threads_pre,
        threads_post,
    );

    let wins = usize::from(result.comparison == "FL_FASTER");
    let losses = usize::from(result.comparison == "FL_SLOWER");
    let undecidable = 1 - wins - losses;
    let verdict = if result.decidable() {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=gethostbyname verdict={verdict} \
         cases=1 wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=localhost_ipv4_hosts_lookup headline_ratio_median={:.6} \
         headline_comparison={} threads_observed_pre={threads_pre} \
         threads_observed_post={threads_post}",
        result.effect_median, result.comparison,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

fn same_f32_bits(left: f32, right: f32) -> bool {
    (left.is_nan() && right.is_nan()) || left.to_bits() == right.to_bits()
}

fn f32_ulp_distance(left: f32, right: f32) -> u32 {
    if left == right {
        return 0;
    }
    if left.is_nan() || right.is_nan() || left.is_sign_negative() != right.is_sign_negative() {
        return u32::MAX;
    }
    left.to_bits().abs_diff(right.to_bits())
}

fn check_f32_hyperbolic_conformance(
    host_sinhf: F32UnaryFn,
    fl_sinhf: F32UnaryFn,
    host_coshf: F32UnaryFn,
    fl_coshf: F32UnaryFn,
) -> (usize, u32, u32) {
    let mut comparisons = 0usize;
    for &input in HYPERBOLIC_SPECIAL_INPUTS {
        let host_sinh = unsafe { host_sinhf(input) };
        let fl_sinh = unsafe { fl_sinhf(input) };
        assert!(
            same_f32_bits(fl_sinh, host_sinh),
            "sinhf special-value mismatch at {input:?}: fl={fl_sinh:?} host={host_sinh:?}"
        );
        comparisons += 1;

        let host_cosh = unsafe { host_coshf(input) };
        let fl_cosh = unsafe { fl_coshf(input) };
        assert!(
            same_f32_bits(fl_cosh, host_cosh),
            "coshf special-value mismatch at {input:?}: fl={fl_cosh:?} host={host_cosh:?}"
        );
        comparisons += 1;
    }

    let mut worst_sinh_ulp = 0u32;
    let mut worst_cosh_ulp = 0u32;
    for &positive in &HYPERBOLIC_MID_INPUTS {
        for input in [positive, -positive] {
            let host_sinh = unsafe { host_sinhf(input) };
            let fl_sinh = unsafe { fl_sinhf(input) };
            let sinh_ulp = f32_ulp_distance(fl_sinh, host_sinh);
            assert!(
                sinh_ulp <= 4,
                "sinhf exceeds 4 ULP at {input:?}: fl={fl_sinh:?} host={host_sinh:?} \
                 ulp={sinh_ulp}"
            );
            worst_sinh_ulp = worst_sinh_ulp.max(sinh_ulp);
            comparisons += 1;

            let host_cosh = unsafe { host_coshf(input) };
            let fl_cosh = unsafe { fl_coshf(input) };
            let cosh_ulp = f32_ulp_distance(fl_cosh, host_cosh);
            assert!(
                cosh_ulp <= 4,
                "coshf exceeds 4 ULP at {input:?}: fl={fl_cosh:?} host={host_cosh:?} \
                 ulp={cosh_ulp}"
            );
            worst_cosh_ulp = worst_cosh_ulp.max(cosh_ulp);
            comparisons += 1;
        }
    }

    (comparisons, worst_sinh_ulp, worst_cosh_ulp)
}

fn run_sinhf_coshf(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_sinhf_symbol = unsafe { libc::dlsym(handle, c"sinhf".as_ptr()) };
    assert!(
        !fl_sinhf_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC sinhf")
    );
    let fl_coshf_symbol = unsafe { libc::dlsym(handle, c"coshf".as_ptr()) };
    assert!(
        !fl_coshf_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC coshf")
    );

    let host_sinhf: F32UnaryFn = linked_host_sinhf;
    let host_coshf: F32UnaryFn = linked_host_coshf;
    let fl_sinhf: F32UnaryFn = unsafe { std::mem::transmute(fl_sinhf_symbol) };
    let fl_coshf: F32UnaryFn = unsafe { std::mem::transmute(fl_coshf_symbol) };
    let incumbent_identity = symbol_object(host_sinhf as *const () as *const c_void)
        .expect("identify host sinhf object");
    let incumbent_coshf_identity = symbol_object(host_coshf as *const () as *const c_void)
        .expect("identify host coshf object");
    let fl_identity =
        symbol_object(fl_sinhf_symbol.cast_const()).expect("identify FrankenLibC sinhf object");
    let fl_coshf_identity =
        symbol_object(fl_coshf_symbol.cast_const()).expect("identify FrankenLibC coshf object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbols=sinhf,coshf");
    println!("FL_LINKAGE explicit_dlopen_local symbols=sinhf,coshf");
    assert!(
        incumbent_identity
            .path
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b"libm.so")),
        "incumbent resolved to {}, not host libm",
        incumbent_identity.path.display()
    );
    assert_eq!(
        incumbent_coshf_identity.sha256, incumbent_identity.sha256,
        "host sinhf and coshf resolve to different serving objects"
    );
    assert_eq!(
        fl_identity.sha256, supplied_fl.sha256,
        "loaded FrankenLibC object differs from supplied object"
    );
    assert_eq!(
        fl_coshf_identity.sha256, fl_identity.sha256,
        "FrankenLibC sinhf and coshf resolve to different serving objects"
    );
    assert_ne!(
        incumbent_identity.sha256, fl_identity.sha256,
        "both providers resolve to byte-identical objects"
    );
    assert_ne!(
        host_sinhf as usize, fl_sinhf as usize,
        "both sinhf arms resolve to the same function address"
    );
    assert_ne!(
        host_coshf as usize, fl_coshf as usize,
        "both coshf arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=sinhf incumbent_address={:#x} fl_address={:#x}",
        host_sinhf as usize, fl_sinhf as usize,
    );
    println!(
        "ARM_DISTINCT symbol=coshf incumbent_address={:#x} fl_address={:#x}",
        host_coshf as usize, fl_coshf as usize,
    );

    let (comparisons, worst_sinh_ulp, worst_cosh_ulp) =
        check_f32_hyperbolic_conformance(host_sinhf, fl_sinhf, host_coshf, fl_coshf);
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbols=sinhf,coshf comparisons={comparisons} \
         special_values_bit_exact=true sweep_inputs_per_sign=64 ulp_limit=4 \
         worst_sinhf_ulp={worst_sinh_ulp} worst_coshf_ulp={worst_cosh_ulp} verdict=pass"
    );
    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbols=sinhf,coshf phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbols=sinhf,coshf verdict=pass");
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
        threads_pre, threads_pre_guard,
        "sinhf/coshf observed thread count changed between conformance and measurement"
    );

    let results = [
        (
            "sinhf",
            measure_f32_unary_case(
                "sinhf_mid_sweep",
                "historical 64-point positive sweep from 0.5 through 6.8",
                host_sinhf,
                fl_sinhf,
            ),
        ),
        (
            "coshf",
            measure_f32_unary_case(
                "coshf_mid_sweep",
                "historical 64-point positive sweep from 0.5 through 6.8",
                host_coshf,
                fl_coshf,
            ),
        ),
    ];

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "sinhf/coshf observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    for (symbol, result) in &results {
        result.print(symbol, &incumbent_identity.path, threads_pre, threads_post);
    }

    let wins = results
        .iter()
        .filter(|(_, result)| result.comparison == "FL_FASTER")
        .count();
    let losses = results
        .iter()
        .filter(|(_, result)| result.comparison == "FL_SLOWER")
        .count();
    let undecidable = results.len() - wins - losses;
    let verdict = if results.iter().all(|(_, result)| result.decidable()) {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbols=sinhf,coshf verdict={verdict} \
         cases={} wins={wins} losses={losses} undecidable={undecidable} \
         threads_observed_pre={threads_pre} threads_observed_post={threads_post}",
        results.len(),
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

/// Destination bytes handed to every `snprintf` probe. Larger than the longest
/// conversion under test so truncation is always a property of the `n` argument
/// and never of the allocation.
const SNPRINTF_BUF: usize = 32;
/// Non-zero fill so an arm that writes nothing is distinguishable from an arm
/// that writes a NUL, and so untouched tail bytes are proved untouched.
const SNPRINTF_CANARY: u8 = 0xa5;
/// The historical row's nine `%u` values: zero, every early decimal-width
/// transition, the 16-bit ceiling, a round seven-digit value, and `u32::MAX`.
const SNPRINTF_U_VALUES: [c_uint; 9] = [0, 9, 10, 99, 100, 999, 65_535, 1_000_000, u32::MAX];
/// The historical row's nine destination sizes, spanning the zero-size,
/// truncation, exact-fit, and one-past-fit final-NUL boundaries.
const SNPRINTF_SIZES: [usize; 9] = [0, 1, 2, 3, 5, 8, 10, 11, 16];
const SNPRINTF_P_VALUES: [usize; 8] = [
    0,
    1,
    0xff,
    0x1000,
    0xdead_beef,
    0x7fff_ffff,
    0x7fff_ffff_ffff,
    usize::MAX,
];
const SNPRINTF_C_VALUES: [c_int; 8] = [0, 0x41, 0x7a, 0x30, 0x20, 0x7e, 0x7f, 0xff];
/// Power-of-two timing tables so the rep loop indexes with a mask. A modulo by
/// nine would put a division in both arms and dilute the ratio under test.
const SNPRINTF_U_TIMING: [c_uint; 8] = [0, 9, 10, 99, 100, 999, 65_535, u32::MAX];

fn snprintf_probe(
    call: impl Fn(*mut c_char, usize) -> c_int,
    size: usize,
) -> (c_int, [u8; SNPRINTF_BUF]) {
    assert!(size <= SNPRINTF_BUF, "probe size {size} exceeds destination");
    let mut buffer = [SNPRINTF_CANARY; SNPRINTF_BUF];
    let returned = call(buffer.as_mut_ptr().cast(), size);
    (returned, buffer)
}

/// Compare both providers on return value AND the complete destination array,
/// including the bytes past `n` that a correct `snprintf` must leave alone.
fn compare_snprintf_probe(
    case: &str,
    format: &str,
    value: &str,
    size: usize,
    host_call: impl Fn(*mut c_char, usize) -> c_int,
    fl_call: impl Fn(*mut c_char, usize) -> c_int,
) -> bool {
    let (host_returned, host_bytes) = snprintf_probe(host_call, size);
    let (fl_returned, fl_bytes) = snprintf_probe(fl_call, size);
    if host_returned == fl_returned && host_bytes == fl_bytes {
        return true;
    }
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE_MISMATCH symbol=snprintf case={case} \
         format={format} value={value} size={size} glibc_return={host_returned} \
         fl_return={fl_returned} glibc_bytes={host_bytes:02x?} fl_bytes={fl_bytes:02x?}"
    );
    false
}

fn check_snprintf_conformance(host: SnprintfFn, fl: SnprintfFn) -> (usize, usize) {
    let mut comparisons = 0usize;
    let mut mismatches = 0usize;

    let unsigned_format = c"%u";
    for &value in &SNPRINTF_U_VALUES {
        for &size in &SNPRINTF_SIZES {
            comparisons += 1;
            if !compare_snprintf_probe(
                "unsigned_decimal",
                "%u",
                &value.to_string(),
                size,
                |pointer, n| unsafe { host(pointer, n, unsigned_format.as_ptr(), value) },
                |pointer, n| unsafe { fl(pointer, n, unsigned_format.as_ptr(), value) },
            ) {
                mismatches += 1;
            }
        }
    }

    let pointer_format = c"%p";
    for &value in &SNPRINTF_P_VALUES {
        let pointer_value = value as *const c_void;
        for &size in &SNPRINTF_SIZES {
            comparisons += 1;
            if !compare_snprintf_probe(
                "pointer",
                "%p",
                &format!("{value:#x}"),
                size,
                |pointer, n| unsafe { host(pointer, n, pointer_format.as_ptr(), pointer_value) },
                |pointer, n| unsafe { fl(pointer, n, pointer_format.as_ptr(), pointer_value) },
            ) {
                mismatches += 1;
            }
        }
    }

    let character_format = c"%c";
    for &value in &SNPRINTF_C_VALUES {
        for &size in &SNPRINTF_SIZES {
            comparisons += 1;
            if !compare_snprintf_probe(
                "character",
                "%c",
                &format!("{value:#04x}"),
                size,
                |pointer, n| unsafe { host(pointer, n, character_format.as_ptr(), value) },
                |pointer, n| unsafe { fl(pointer, n, character_format.as_ptr(), value) },
            ) {
                mismatches += 1;
            }
        }
    }

    (comparisons, mismatches)
}

#[inline(never)]
fn run_snprintf_u_batch(function: SnprintfFn) -> u64 {
    let format = c"%u";
    let mut buffer = [0u8; SNPRINTF_BUF];
    let mut accumulator = 0xcbf2_9ce4_8422_2325u64;
    for index in 0..SNPRINTF_REPS {
        let value = SNPRINTF_U_TIMING[index & (SNPRINTF_U_TIMING.len() - 1)];
        let returned = unsafe {
            black_box(function)(
                black_box(buffer.as_mut_ptr().cast()),
                black_box(SNPRINTF_BUF),
                black_box(format.as_ptr()),
                black_box(value),
            )
        };
        accumulator ^= black_box(returned) as u64;
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    }
    black_box(buffer);
    black_box(accumulator)
}

#[inline(never)]
fn run_snprintf_p_batch(function: SnprintfFn) -> u64 {
    let format = c"%p";
    let mut buffer = [0u8; SNPRINTF_BUF];
    let mut accumulator = 0xcbf2_9ce4_8422_2325u64;
    for index in 0..SNPRINTF_REPS {
        let value = SNPRINTF_P_VALUES[index & (SNPRINTF_P_VALUES.len() - 1)] as *const c_void;
        let returned = unsafe {
            black_box(function)(
                black_box(buffer.as_mut_ptr().cast()),
                black_box(SNPRINTF_BUF),
                black_box(format.as_ptr()),
                black_box(value),
            )
        };
        accumulator ^= black_box(returned) as u64;
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    }
    black_box(buffer);
    black_box(accumulator)
}

#[inline(never)]
fn run_snprintf_c_batch(function: SnprintfFn) -> u64 {
    let format = c"%c";
    let mut buffer = [0u8; SNPRINTF_BUF];
    let mut accumulator = 0xcbf2_9ce4_8422_2325u64;
    for index in 0..SNPRINTF_REPS {
        let value = SNPRINTF_C_VALUES[index & (SNPRINTF_C_VALUES.len() - 1)];
        let returned = unsafe {
            black_box(function)(
                black_box(buffer.as_mut_ptr().cast()),
                black_box(SNPRINTF_BUF),
                black_box(format.as_ptr()),
                black_box(value),
            )
        };
        accumulator ^= black_box(returned) as u64;
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    }
    black_box(buffer);
    black_box(accumulator)
}

fn time_snprintf_u_batch(function: SnprintfFn) -> f64 {
    let started = Instant::now();
    black_box(run_snprintf_u_batch(function));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / SNPRINTF_REPS as f64
}

fn time_snprintf_p_batch(function: SnprintfFn) -> f64 {
    let started = Instant::now();
    black_box(run_snprintf_p_batch(function));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / SNPRINTF_REPS as f64
}

fn time_snprintf_c_batch(function: SnprintfFn) -> f64 {
    let started = Instant::now();
    black_box(run_snprintf_c_batch(function));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / SNPRINTF_REPS as f64
}

fn measure_snprintf_case(
    label: &'static str,
    note: &'static str,
    host: SnprintfFn,
    fl: SnprintfFn,
    time_batch: fn(SnprintfFn) -> f64,
) -> CaseResult {
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
                    fa = time_batch(fl);
                    fb = time_batch(fl);
                }
                0 => {
                    fb = time_batch(fl);
                    fa = time_batch(fl);
                }
                1 if sample % 2 == 0 => {
                    ga = time_batch(host);
                    gb = time_batch(host);
                }
                1 => {
                    gb = time_batch(host);
                    ga = time_batch(host);
                }
                2 if sample % 2 == 0 => {
                    effect_fl = time_batch(fl);
                    effect_glibc = time_batch(host);
                }
                2 => {
                    effect_glibc = time_batch(host);
                    effect_fl = time_batch(fl);
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

    summarize_case(
        label,
        note,
        SNPRINTF_REPS,
        fl_effect,
        glibc_effect,
        fl_null_a,
        fl_null_b,
        glibc_null_a,
        glibc_null_b,
    )
}

fn run_snprintf(config: &Config) {
    let supplied_fl = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied_fl.path.as_os_str().as_bytes()).expect("FrankenLibC path has NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));
    let fl_symbol = unsafe { libc::dlsym(handle, c"snprintf".as_ptr()) };
    assert!(
        !fl_symbol.is_null(),
        "{}",
        dl_error("dlsym FrankenLibC snprintf")
    );

    let host: SnprintfFn = linked_host_snprintf;
    let fl: SnprintfFn = unsafe { std::mem::transmute(fl_symbol) };
    let incumbent_identity =
        symbol_object(host as *const () as *const c_void).expect("identify host snprintf object");
    let fl_identity =
        symbol_object(fl_symbol.cast_const()).expect("identify FrankenLibC snprintf object");
    print_identity("INCUMBENT", &incumbent_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbol=snprintf");
    println!("FL_LINKAGE explicit_dlopen_local symbol=snprintf");
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
        "both providers resolve to byte-identical objects"
    );
    assert_ne!(
        host as usize, fl as usize,
        "both snprintf arms resolve to the same function address"
    );
    println!(
        "ARM_DISTINCT symbol=snprintf incumbent_address={:#x} fl_address={:#x}",
        host as usize, fl as usize,
    );

    let (comparisons, mismatches) = check_snprintf_conformance(host, fl);
    let conformance_verdict = if mismatches == 0 { "pass" } else { "fail" };
    println!(
        "INCUMBENT_COVERAGE_CONFORMANCE symbol=snprintf formats=%u,%p,%c \
         values_per_format=9,8,8 destination_sizes=9 destination_bytes={SNPRINTF_BUF} \
         comparisons={comparisons} mismatches={mismatches} \
         compared=return_value_and_full_destination verdict={conformance_verdict}"
    );
    let threads_pre_guard = observed_threads();
    println!("THREADS_OBSERVED symbol=snprintf phase=pre_guard count={threads_pre_guard}");
    if config.verify_only {
        println!("INCUMBENT_COVERAGE_VERIFY_ONLY symbol=snprintf verdict={conformance_verdict}");
        if mismatches > 0 {
            std::process::exit(2);
        }
        return;
    }
    assert_eq!(
        mismatches, 0,
        "snprintf arms are not observationally equivalent; refusing to time them"
    );

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
        threads_pre, threads_pre_guard,
        "snprintf observed thread count changed between conformance and measurement"
    );

    let results = [
        measure_snprintf_case(
            "unsigned_decimal_bare",
            "historical bd-gldi10 headline: bare \"%u\" over eight decimal widths",
            host,
            fl,
            time_snprintf_u_batch,
        ),
        measure_snprintf_case(
            "pointer_bare",
            "historical pointer-formatter claim: bare \"%p\" over eight magnitudes",
            host,
            fl,
            time_snprintf_p_batch,
        ),
        measure_snprintf_case(
            "character_bare",
            "historical character claim: bare \"%c\" over eight byte values",
            host,
            fl,
            time_snprintf_c_batch,
        ),
    ];

    let threads_post = observed_threads();
    assert_eq!(
        threads_post, threads_pre,
        "snprintf observed thread count changed during measurement"
    );
    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("INCUMBENT_COVERAGE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));
    for result in &results {
        result.print(
            "snprintf",
            &incumbent_identity.path,
            threads_pre,
            threads_post,
        );
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
        .find(|result| result.label == "unsigned_decimal_bare")
        .expect("missing unsigned_decimal_bare result");
    let verdict = if results.iter().all(CaseResult::decidable) {
        "DECIDABLE"
    } else {
        "INCOMPLETE"
    };
    println!(
        "INCUMBENT_COVERAGE_VERDICT symbol=snprintf verdict={verdict} \
         cases={} wins={wins} losses={losses} undecidable={undecidable} \
         headline_case=unsigned_decimal_bare headline_ratio_median={:.6} \
         threads_observed_pre={threads_pre} threads_observed_post={threads_post}",
        results.len(),
        headline.effect_median,
    );

    // The loaded libc replacement owns process-global and TLS state. Keep it
    // resident until process exit rather than attempting an unsupported unload.
    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}

fn main() {
    let config = parse_args();
    ensure_fl_shared_object(&config);
    if !config.families.is_empty() {
        run_families(&config);
    }
    pin_to_quietest(config.pin_quietest);
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

    match config.family {
        Family::NlLanginfo => run_nl_langinfo(&config),
        Family::Getrandom => run_getrandom(&config),
        Family::Getauxval => run_getauxval(&config),
        Family::SemPost => run_sem_post(&config),
        Family::ThrdCurrent => run_thrd_current(&config),
        Family::MtxTrylock => run_mtx_trylock(&config),
        Family::GetaddrinfoHosts => run_getaddrinfo_hosts(&config),
        Family::SinhfCoshf => run_sinhf_coshf(&config),
        Family::Gethostbyaddr => run_gethostbyaddr(&config),
        Family::Gethostbyname => run_gethostbyname(&config),
        Family::Snprintf => run_snprintf(&config),
    }
}
