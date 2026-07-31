//! Falsifiable mechanism test #2: the glibc `LC_CTYPE` name/descriptor bridge.
//!
//! SHARP MECHANISM (unchanged from the `rpmatch` test it must now generalise).
//! A FrankenLibC specialization advantage is predicted only when:
//!   (a) the claimed semantic slice is closed and full-domain equivalence is
//!       proved,
//!   (b) glibc still dispatches a data-driven interpretation on every call
//!       after all legitimate caching/hoisting, and
//!   (c) the deployed FrankenLibC path is already a bounded, allocation-free
//!       decision procedure rather than a second general interpreter.
//!
//! WHY THIS FAMILY. `<wctype.h>`'s name bridge splits THREE ways on those
//! conditions inside one header, one locale and one measurement run, so (b)
//! and (c) each have to earn their place instead of riding along with (a):
//!
//!   * `wctype(name)` satisfies (a), (b) and (c). Disassembly of the shipped
//!     glibc 2.42 `wctype` shows a per-call `strlen` of the argument, a TLS
//!     load of the current `LC_CTYPE` locale, and then a linear walk of the
//!     NUL-separated class-name table doing one `strlen` per entry plus a
//!     `memcmp` whenever the lengths match. Nothing about that is hoistable:
//!     the argument is a runtime string. FrankenLibC answers with a borrowed
//!     bounded slice (`bounded_cstr_bytes`, no allocation) and a closed match
//!     over twelve literals.
//!     => PREDICT `FL_FASTER`, large, on every case.
//!
//!   * `wctrans(name)` satisfies (a) and (b) in form but FAILS (c):
//!     FrankenLibC's `wctrans` reads its argument with `read_c_string_bytes`,
//!     which ends in `.to_vec()` — one heap allocation on every call — while
//!     glibc's C-locale map table is only TWO entries deep, so the incumbent
//!     walk it has to beat is at most two `strcmp`s.
//!     => PREDICT no large win, and specifically that FrankenLibC's ratio is
//!        WORSE on every `wctrans` case than on every `wctype` case. This is
//!        the bold half of the test: the naive "glibc walks a table, so we
//!        win" reading predicts a win here and the mechanism predicts none.
//!
//!   * `iswctype(wc, desc)` satisfies (a) and (c) but FAILS (b): glibc's
//!     `__iswctype` is about twenty branchless instructions — three shift/mask
//!     /load trie probes, no calls, no loop. The expensive name work already
//!     happened in `wctype`, which is precisely what "after all legitimate
//!     hoisting" means.
//!     => PREDICT no large FrankenLibC win.
//!
//! REGISTERED SHAPE, fixed before timing. The C-locale table order was read
//! through the public `nl_langinfo` API (see `REGISTERED_CLASS_ORDER`), so the
//! walk cost is predicted to be monotone in table position:
//!   S1  glibc `wctype` is slower for `alnum` (index 11) than for `upper`
//!       (index 0);
//!   S2  glibc `wctype` for an unrecognised name is at least as slow as its
//!       slowest recognised name, because a miss cannot break out early;
//!   S3  glibc `wctype` time correlates with table index at rho >= 0.9 over
//!       the eleven five-byte class names. `xdigit` is excluded from the
//!       correlation and reported separately: it is the only six-byte name, so
//!       the length test skips the `memcmp` for every other entry and it is
//!       expected to sit BELOW the trend line for its index;
//!   S4  FrankenLibC's `wctype` time is flat across the twelve class names
//!       (max/min <= 1.5), because a closed match does not walk.
//!
//! HOW THE SLICE HAD TO BE NARROWED BEFORE TIMING. Two things were found while
//! establishing (a), and both restrict what this run is allowed to claim:
//!
//!   1. `wctype_t` and `wctrans_t` are OPAQUE. glibc returns pointers into its
//!      locale table; FrankenLibC returns small integers. The descriptors are
//!      not comparable and equality of return values is NOT the conformance
//!      contract. The observable semantics are (i) the recognition decision,
//!      zero versus non-zero, and (ii) the COMPOSITION `iswctype(wc,
//!      wctype(name))` / `towctrans(wc, wctrans(name))`. Both are proved here,
//!      and each arm is always given the descriptor minted by its own library.
//!
//!   2. FrankenLibC's wide ctype is locale-agnostic and targets glibc's
//!      *C.UTF-8* classification, while this benchmark runs in the C locale
//!      where glibc classifies ASCII only. So the composition slice claimed
//!      here is ASCII, `0x00..=0x7F`, where the two agree by construction. The
//!      C-locale *name* tables, by contrast, are exactly the twelve POSIX
//!      classes and two maps FrankenLibC knows, so name recognition is claimed
//!      over a full name domain. A post-timing C.UTF-8 census is printed as a
//!      registered observation, not as a gate: C.UTF-8 adds `combining`,
//!      `combining_level3` and `totitle`, which FrankenLibC does not know.
//!
//! Contract:
//!   * host `wctype`/`wctrans`/`iswctype`/`towctrans` are linked normally in
//!     the process base namespace;
//!   * FrankenLibC is loaded from an explicit shared-object path with `dlopen`;
//!   * the benchmark ELF and both serving objects self-report SHA-256;
//!   * every arm pair must resolve to distinct objects or the run aborts;
//!   * the runtime `nl_langinfo` table order must equal the registered order;
//!   * conformance precedes timing;
//!   * every case carries FL/FL and glibc/glibc A/A controls;
//!   * bootstrap-median CIs and the corrected median-bias/2x-null rule decide;
//!   * CV is telemetry only.

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_ulong, c_void};
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

/// `nl_langinfo` items for the two `LC_CTYPE` name tables. LC_CTYPE is
/// category zero, so the raw enum values double as the `nl_item` codes.
const NL_CTYPE_CLASS_NAMES: c_int = 10;
const NL_CTYPE_MAP_NAMES: c_int = 11;

/// C-locale class-name table order, read through `nl_langinfo` BEFORE any
/// timing and frozen here so the position shape is a prediction, not a
/// post-hoc description. Asserted against the measurement host at runtime.
const REGISTERED_CLASS_ORDER: &[&str] = &[
    "upper", "lower", "alpha", "digit", "xdigit", "space", "print", "graph", "blank", "cntrl",
    "punct", "alnum",
];

/// C-locale map-name table order, same provenance.
const REGISTERED_MAP_ORDER: &[&str] = &["toupper", "tolower"];

/// The eleven five-byte class names. `xdigit` is the only six-byte name, so it
/// is excluded from the monotone correlation and reported on its own.
const MONOTONE_SUBSET: &[&str] = &[
    "upper", "lower", "alpha", "digit", "space", "print", "graph", "blank", "cntrl", "punct",
    "alnum",
];

/// Names that exist in C.UTF-8 but not in the C locale, and that FrankenLibC
/// does not implement. Both sides must answer zero in the C locale.
const UTF8_ONLY_CLASS_NAMES: &[&str] = &["combining", "combining_level3"];
const UTF8_ONLY_MAP_NAMES: &[&str] = &["totitle"];

type NameFn = unsafe extern "C" fn(*const c_char) -> c_ulong;
type IswFn = unsafe extern "C" fn(u32, c_ulong) -> c_int;
type TowFn = unsafe extern "C" fn(u32, c_ulong) -> u32;

unsafe extern "C" {
    #[link_name = "wctype"]
    fn linked_host_wctype(name: *const c_char) -> c_ulong;
    #[link_name = "wctrans"]
    fn linked_host_wctrans(name: *const c_char) -> c_ulong;
    #[link_name = "iswctype"]
    fn linked_host_iswctype(wc: u32, desc: c_ulong) -> c_int;
    #[link_name = "towctrans"]
    fn linked_host_towctrans(wc: u32, desc: c_ulong) -> u32;
    #[link_name = "setlocale"]
    fn linked_host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
    #[link_name = "nl_langinfo"]
    fn linked_host_nl_langinfo(item: c_int) -> *mut c_char;
}

struct Config {
    fl_so: PathBuf,
    verify_only: bool,
}

/// The four FrankenLibC entry points under test, resolved out of one
/// explicitly loaded strict object.
struct FlSymbols {
    wctype: NameFn,
    wctrans: NameFn,
    iswctype: IswFn,
    towctrans: TowFn,
    wctype_address: *const c_void,
    wctrans_address: *const c_void,
    iswctype_address: *const c_void,
    towctrans_address: *const c_void,
}

#[derive(Debug)]
struct ObjectIdentity {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct CaseResult {
    group: &'static str,
    symbol: &'static str,
    label: String,
    note: String,
    /// Table index for `wctype`/`wctrans` cases; `-1` where position has no
    /// meaning (descriptor application, or an unrecognised name).
    table_index: i32,
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
        self.fl_null_holds
            && self.glibc_null_holds
            && self.clears_2x_null
            && (self.effect_high < 1.0 || self.effect_low > 1.0)
    }

    fn print(&self, host_path: &Path) {
        println!(
            "WCTYPE group={} case={} symbol={} table_index={} host={} \
             threads_actually_used=1 samples={} reps_per_arm={} \
             fl_median_ns={:.3} glibc_median_ns={:.3} note={:?}",
            self.group,
            self.label,
            self.symbol,
            self.table_index,
            host_path.display(),
            SAMPLES - WARMUPS,
            REPS,
            self.fl_median_ns,
            self.glibc_median_ns,
            self.note,
        );
        println!(
            "WCTYPE_CONTRACT group={} case={} symbol={} kind=null_fl_fl \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
             null_holds={}",
            self.group,
            self.label,
            self.symbol,
            self.fl_null_median,
            self.fl_null_low,
            self.fl_null_high,
            self.fl_null_cv_pct,
            self.fl_null_mad,
            self.fl_null_holds,
        );
        println!(
            "WCTYPE_CONTRACT group={} case={} symbol={} kind=null_glibc_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} \
             null_holds={}",
            self.group,
            self.label,
            self.symbol,
            self.glibc_null_median,
            self.glibc_null_low,
            self.glibc_null_high,
            self.glibc_null_cv_pct,
            self.glibc_null_mad,
            self.glibc_null_holds,
        );
        println!(
            "WCTYPE_CONTRACT group={} case={} symbol={} kind=fl_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             ratio_mad={:.6} null_half_width={:.6} clears_2x_null={} \
             nulls_hold={} comparison={} cv_role=telemetry_only \
             gate=corrected_null_median_bias",
            self.group,
            self.label,
            self.symbol,
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
                "unknown argument {:?}; usage: wctype_ab --fl-so PATH [--verify-only]",
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

// ---------------------------------------------------------------------------
// Statistics — identical to the rpmatch harness, corrected null gate.
// ---------------------------------------------------------------------------

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

/// Spearman rank correlation. Table indices are distinct and the timings are
/// continuous, so plain ranks with midpoint ties are sufficient here.
fn spearman(xs: &[f64], ys: &[f64]) -> f64 {
    assert_eq!(xs.len(), ys.len(), "spearman needs paired samples");
    let rank = |values: &[f64]| -> Vec<f64> {
        let mut order: Vec<usize> = (0..values.len()).collect();
        order.sort_by(|&a, &b| values[a].total_cmp(&values[b]));
        let mut ranks = vec![0.0; values.len()];
        let mut index = 0;
        while index < order.len() {
            let mut end = index + 1;
            while end < order.len() && values[order[end]] == values[order[index]] {
                end += 1;
            }
            let shared = (index + end - 1) as f64 / 2.0;
            for slot in &order[index..end] {
                ranks[*slot] = shared;
            }
            index = end;
        }
        ranks
    };
    let rx = rank(xs);
    let ry = rank(ys);
    let mx = mean(&rx);
    let my = mean(&ry);
    let mut num = 0.0;
    let mut dx = 0.0;
    let mut dy = 0.0;
    for (a, b) in rx.iter().zip(&ry) {
        num += (a - mx) * (b - my);
        dx += (a - mx) * (a - mx);
        dy += (b - my) * (b - my);
    }
    if dx == 0.0 || dy == 0.0 {
        return 0.0;
    }
    num / (dx.sqrt() * dy.sqrt())
}

// ---------------------------------------------------------------------------
// Timed batches. One `#[inline(never)]` loop per signature; both arms of a
// pair run the identical loop so its overhead cancels in the ratio.
// ---------------------------------------------------------------------------

#[inline(never)]
fn run_name_batch(function: NameFn, name: *const c_char) -> u64 {
    let mut accumulator = 0u64;
    for _ in 0..REPS {
        let result = unsafe { function(black_box(name)) };
        accumulator = accumulator.wrapping_add(result as u64);
    }
    black_box(accumulator)
}

#[inline(never)]
fn run_isw_batch(function: IswFn, wc: u32, desc: c_ulong) -> i64 {
    let mut accumulator = 0i64;
    for _ in 0..REPS {
        let result = unsafe { function(black_box(wc), black_box(desc)) };
        accumulator = accumulator.wrapping_add(i64::from(result));
    }
    black_box(accumulator)
}

#[inline(never)]
fn run_tow_batch(function: TowFn, wc: u32, desc: c_ulong) -> u64 {
    let mut accumulator = 0u64;
    for _ in 0..REPS {
        let result = unsafe { function(black_box(wc), black_box(desc)) };
        accumulator = accumulator.wrapping_add(u64::from(result));
    }
    black_box(accumulator)
}

fn time_name(function: NameFn, name: *const c_char) -> f64 {
    let started = Instant::now();
    black_box(run_name_batch(function, name));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

fn time_isw(function: IswFn, wc: u32, desc: c_ulong) -> f64 {
    let started = Instant::now();
    black_box(run_isw_batch(function, wc, desc));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

fn time_tow(function: TowFn, wc: u32, desc: c_ulong) -> f64 {
    let started = Instant::now();
    black_box(run_tow_batch(function, wc, desc));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

/// Shared measurement protocol: three rotated pair kinds per sample, arm order
/// inside the effect pair alternating, warmups dropped, corrected null gate.
#[allow(clippy::too_many_arguments)]
fn measure_case<F, G>(
    group: &'static str,
    symbol: &'static str,
    label: String,
    note: String,
    table_index: i32,
    mut fl_time: F,
    mut glibc_time: G,
) -> CaseResult
where
    F: FnMut() -> f64,
    G: FnMut() -> f64,
{
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

        for slot in 0..3 {
            match (sample + slot) % 3 {
                0 => {
                    fa = fl_time();
                    fb = fl_time();
                }
                1 => {
                    ga = glibc_time();
                    gb = glibc_time();
                }
                2 if sample % 2 == 0 => {
                    effect_fl = fl_time();
                    effect_glibc = glibc_time();
                }
                2 => {
                    effect_glibc = glibc_time();
                    effect_fl = fl_time();
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
        group,
        symbol,
        label,
        note,
        table_index,
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

// ---------------------------------------------------------------------------
// Locale table provenance.
// ---------------------------------------------------------------------------

/// Walk a NUL-separated, double-NUL-terminated `nl_langinfo` name table.
fn read_name_table(item: c_int) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = unsafe { linked_host_nl_langinfo(item) };
    if cursor.is_null() {
        return names;
    }
    loop {
        let entry = unsafe { CStr::from_ptr(cursor) };
        let bytes = entry.to_bytes();
        if bytes.is_empty() {
            break;
        }
        names.push(String::from_utf8_lossy(bytes).into_owned());
        cursor = unsafe { cursor.add(bytes.len() + 1) };
    }
    names
}

// ---------------------------------------------------------------------------
// Conformance. Descriptors are opaque, so the contract is the recognition
// decision plus the composition, never descriptor equality.
// ---------------------------------------------------------------------------

fn c_name(bytes: &[u8]) -> CString {
    CString::new(bytes).expect("conformance name must not contain NUL")
}

/// Both libraries must agree on whether a name is recognised at all.
fn verify_recognition(
    host: NameFn,
    fl: NameFn,
    symbol: &str,
    bytes: &[u8],
    expect_known: bool,
) -> usize {
    let name = c_name(bytes);
    let host_desc = unsafe { host(name.as_ptr()) };
    let fl_desc = unsafe { fl(name.as_ptr()) };
    let host_known = host_desc != 0;
    let fl_known = fl_desc != 0;
    assert_eq!(
        host_known,
        expect_known,
        "{symbol} recognition contract broke on the incumbent for {:?}: \
         glibc known={host_known}, registered expectation={expect_known}",
        String::from_utf8_lossy(bytes),
    );
    assert_eq!(
        fl_known,
        host_known,
        "{symbol} recognition mismatch for {:?}: FrankenLibC known={fl_known}, \
         glibc known={host_known}",
        String::from_utf8_lossy(bytes),
    );
    1
}

/// Every non-name we can afford to enumerate, shared by both name tables.
fn unknown_name_domain(known: &[&str]) -> Vec<Vec<u8>> {
    let mut domain: Vec<Vec<u8>> = Vec::new();
    domain.push(Vec::new());
    for lead in 1u16..=255 {
        domain.push(vec![lead as u8]);
    }
    for lead in 1u16..=255 {
        for tail in 1u16..=255 {
            domain.push(vec![lead as u8, tail as u8]);
        }
    }
    for name in known {
        let bytes = name.as_bytes();
        for cut in 1..bytes.len() {
            domain.push(bytes[..cut].to_vec());
            domain.push(bytes[cut..].to_vec());
        }
        domain.push(name.to_uppercase().into_bytes());
        let mut trailing = bytes.to_vec();
        trailing.push(b'x');
        domain.push(trailing);
        let mut leading = vec![b'x'];
        leading.extend_from_slice(bytes);
        domain.push(leading);
        let mut spaced = bytes.to_vec();
        spaced.push(b' ');
        domain.push(spaced);
    }
    for extra in UTF8_ONLY_CLASS_NAMES.iter().chain(UTF8_ONLY_MAP_NAMES) {
        domain.push(extra.as_bytes().to_vec());
    }
    domain.retain(|candidate| {
        !known
            .iter()
            .any(|name| name.as_bytes() == candidate.as_slice())
    });
    domain
}

fn verify_conformance(
    host_wctype: NameFn,
    host_wctrans: NameFn,
    host_iswctype: IswFn,
    host_towctrans: TowFn,
    fl: &FlSymbols,
) -> (usize, usize, usize) {
    let mut recognition = 0usize;

    for name in REGISTERED_CLASS_ORDER {
        recognition += verify_recognition(
            host_wctype,
            fl.wctype,
            "wctype",
            name.as_bytes(),
            true,
        );
    }
    for name in REGISTERED_MAP_ORDER {
        recognition += verify_recognition(
            host_wctrans,
            fl.wctrans,
            "wctrans",
            name.as_bytes(),
            true,
        );
    }
    for candidate in unknown_name_domain(REGISTERED_CLASS_ORDER) {
        recognition += verify_recognition(
            host_wctype,
            fl.wctype,
            "wctype",
            &candidate,
            false,
        );
    }
    for candidate in unknown_name_domain(REGISTERED_MAP_ORDER) {
        recognition += verify_recognition(
            host_wctrans,
            fl.wctrans,
            "wctrans",
            &candidate,
            false,
        );
    }

    // Composition over the claimed ASCII slice. Each arm applies the
    // descriptor minted by its own library, which is the only well-defined
    // way to compare opaque handles.
    let mut class_composition = 0usize;
    for name in REGISTERED_CLASS_ORDER {
        let name = c_name(name.as_bytes());
        let host_desc = unsafe { host_wctype(name.as_ptr()) };
        let fl_desc = unsafe { (fl.wctype)(name.as_ptr()) };
        for wc in 0u32..=0x7F {
            let host_bit = unsafe { host_iswctype(wc, host_desc) } != 0;
            let fl_bit = unsafe { (fl.iswctype)(wc, fl_desc) } != 0;
            assert_eq!(
                fl_bit,
                host_bit,
                "iswctype composition mismatch for class {:?} at U+{wc:04X}: \
                 FrankenLibC={fl_bit}, glibc={host_bit}",
                name.to_string_lossy(),
            );
            class_composition += 1;
        }
    }

    let mut map_composition = 0usize;
    for name in REGISTERED_MAP_ORDER {
        let name = c_name(name.as_bytes());
        let host_desc = unsafe { host_wctrans(name.as_ptr()) };
        let fl_desc = unsafe { (fl.wctrans)(name.as_ptr()) };
        for wc in 0u32..=0x7F {
            let host_mapped = unsafe { host_towctrans(wc, host_desc) };
            let fl_mapped = unsafe { (fl.towctrans)(wc, fl_desc) };
            assert_eq!(
                fl_mapped,
                host_mapped,
                "towctrans composition mismatch for map {:?} at U+{wc:04X}: \
                 FrankenLibC={fl_mapped}, glibc={host_mapped}",
                name.to_string_lossy(),
            );
            map_composition += 1;
        }
    }

    // A zero descriptor must be inert on both sides.
    for wc in 0u32..=0x7F {
        let host_bit = unsafe { host_iswctype(wc, 0) } != 0;
        let fl_bit = unsafe { (fl.iswctype)(wc, 0) } != 0;
        assert_eq!(
            fl_bit, host_bit,
            "iswctype with a zero descriptor diverged at U+{wc:04X}"
        );
        class_composition += 1;
    }

    (recognition, class_composition, map_composition)
}

/// Registered post-timing observation: FrankenLibC's wide ctype is
/// locale-agnostic, so C.UTF-8's extra names are expected to diverge. Printed,
/// never gated, and run only after every measurement has been taken.
fn utf8_name_census(host_wctype: NameFn, host_wctrans: NameFn, fl: &FlSymbols) {
    let utf8 = CString::new("C.UTF-8").expect("locale name");
    if unsafe { linked_host_setlocale(libc::LC_ALL, utf8.as_ptr()) }.is_null() {
        println!("WCTYPE_UTF8_CENSUS status=unavailable locale=C.UTF-8");
        return;
    }
    let classes = read_name_table(NL_CTYPE_CLASS_NAMES);
    let maps = read_name_table(NL_CTYPE_MAP_NAMES);
    let mut divergences = 0usize;
    let mut detail = String::new();
    for (symbol, table, function) in [
        ("wctype", &classes, fl.wctype),
        ("wctrans", &maps, fl.wctrans),
    ] {
        let host = if symbol == "wctype" {
            host_wctype
        } else {
            host_wctrans
        };
        for name in table {
            let cname = c_name(name.as_bytes());
            let host_known = unsafe { host(cname.as_ptr()) } != 0;
            let fl_known = unsafe { function(cname.as_ptr()) } != 0;
            if host_known != fl_known {
                divergences += 1;
                let _ = write!(
                    &mut detail,
                    " {symbol}:{name}(glibc={host_known},fl={fl_known})"
                );
            }
        }
    }
    println!(
        "WCTYPE_UTF8_CENSUS status=ran locale=C.UTF-8 class_names={} map_names={} \
         divergences={divergences} detail={:?} role=registered_observation_not_a_gate",
        classes.len(),
        maps.len(),
        detail.trim(),
    );
}

// ---------------------------------------------------------------------------
// Prediction adjudication.
// ---------------------------------------------------------------------------

struct Verdict {
    verdict: &'static str,
    wctype_all_faster: bool,
    shape_endpoints: bool,
    shape_unknown_slowest: bool,
    shape_rho: f64,
    shape_monotone: bool,
    shape_fl_flat: bool,
    fl_flat_ratio: f64,
    iswctype_no_large_win: bool,
    wctrans_worse_than_wctype: bool,
    wctrans_not_a_win: bool,
    worst_wctype_ratio: f64,
    best_wctrans_ratio: f64,
    best_iswctype_ratio: f64,
    xdigit_below_trend: bool,
}

fn adjudicate(results: &[CaseResult]) -> Verdict {
    let group = |name: &str| -> Vec<&CaseResult> {
        results.iter().filter(|row| row.group == name).collect()
    };
    let wctype_rows = group("wctype");
    let wctrans_rows = group("wctrans");
    let iswctype_rows = group("iswctype");

    let all_decidable = results.iter().all(CaseResult::decidable);

    // P1 — every wctype case is a FrankenLibC win.
    let wctype_all_faster = wctype_rows
        .iter()
        .all(|row| row.comparison == "FL_FASTER" && row.effect_high < 1.0);

    // Registered shape S1..S4 over the recognised class names.
    let named = |label: &str| -> &CaseResult {
        wctype_rows
            .iter()
            .find(|row| row.label == label)
            .unwrap_or_else(|| panic!("missing wctype row {label}"))
    };
    let classes: Vec<&CaseResult> = REGISTERED_CLASS_ORDER.iter().map(|name| named(name)).collect();

    let shape_endpoints = named("alnum").glibc_median_ns > named("upper").glibc_median_ns;
    let slowest_known = classes
        .iter()
        .map(|row| row.glibc_median_ns)
        .fold(f64::MIN, f64::max);
    let shape_unknown_slowest = named("unknown").glibc_median_ns >= slowest_known;

    let monotone_indices: Vec<f64> = MONOTONE_SUBSET
        .iter()
        .map(|name| {
            REGISTERED_CLASS_ORDER
                .iter()
                .position(|entry| entry == name)
                .expect("monotone subset is drawn from the registered order") as f64
        })
        .collect();
    let monotone_times: Vec<f64> = MONOTONE_SUBSET
        .iter()
        .map(|name| named(name).glibc_median_ns)
        .collect();
    let shape_rho = spearman(&monotone_indices, &monotone_times);
    let shape_monotone = shape_rho >= 0.9;

    let fl_max = classes
        .iter()
        .map(|row| row.fl_median_ns)
        .fold(f64::MIN, f64::max);
    let fl_min = classes
        .iter()
        .map(|row| row.fl_median_ns)
        .fold(f64::MAX, f64::min);
    let fl_flat_ratio = if fl_min > 0.0 { fl_max / fl_min } else { f64::MAX };
    let shape_fl_flat = fl_flat_ratio <= 1.5;

    // Registered secondary: xdigit is the only six-byte name, so the length
    // test skips the memcmp for every other entry and it should sit below the
    // fitted trend for its index.
    let xdigit = named("xdigit");
    let trend_at = |index: f64| -> f64 {
        let mx = mean(&monotone_indices);
        let my = mean(&monotone_times);
        let mut num = 0.0;
        let mut den = 0.0;
        for (x, y) in monotone_indices.iter().zip(&monotone_times) {
            num += (x - mx) * (y - my);
            den += (x - mx) * (x - mx);
        }
        if den == 0.0 { my } else { my + (num / den) * (index - mx) }
    };
    let xdigit_below_trend = xdigit.glibc_median_ns < trend_at(4.0);

    // P3 — iswctype fails condition (b), so no large win. "Large" is fixed in
    // advance at 2x, i.e. an effect ratio below 0.5.
    let best_iswctype_ratio = iswctype_rows
        .iter()
        .map(|row| row.effect_median)
        .fold(f64::MAX, f64::min);
    let iswctype_no_large_win = best_iswctype_ratio > 0.5;

    // P4 — wctrans fails condition (c), so its best ratio must be worse than
    // the worst wctype ratio.
    let worst_wctype_ratio = wctype_rows
        .iter()
        .map(|row| row.effect_median)
        .fold(f64::MIN, f64::max);
    let best_wctrans_ratio = wctrans_rows
        .iter()
        .map(|row| row.effect_median)
        .fold(f64::MAX, f64::min);
    let wctrans_worse_than_wctype = best_wctrans_ratio > worst_wctype_ratio;
    // Bold sub-prediction, reported but not gating.
    let wctrans_not_a_win = wctrans_rows
        .iter()
        .any(|row| row.comparison != "FL_FASTER");

    let verdict = if !all_decidable {
        "INCOMPLETE"
    } else if wctype_all_faster
        && shape_endpoints
        && shape_unknown_slowest
        && shape_monotone
        && shape_fl_flat
        && iswctype_no_large_win
        && wctrans_worse_than_wctype
    {
        "CONFIRMED"
    } else {
        "REFUTED"
    };

    Verdict {
        verdict,
        wctype_all_faster,
        shape_endpoints,
        shape_unknown_slowest,
        shape_rho,
        shape_monotone,
        shape_fl_flat,
        fl_flat_ratio,
        iswctype_no_large_win,
        wctrans_worse_than_wctype,
        wctrans_not_a_win,
        worst_wctype_ratio,
        best_wctrans_ratio,
        best_iswctype_ratio,
        xdigit_below_trend,
    }
}

// ---------------------------------------------------------------------------

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

    // The registered position shape is only meaningful against the table this
    // host actually serves, so prove they are the same table.
    let runtime_classes = read_name_table(NL_CTYPE_CLASS_NAMES);
    let runtime_maps = read_name_table(NL_CTYPE_MAP_NAMES);
    println!(
        "WCTYPE_TABLE locale=C class_count={} class_order={} map_count={} map_order={}",
        runtime_classes.len(),
        runtime_classes.join(","),
        runtime_maps.len(),
        runtime_maps.join(","),
    );
    assert_eq!(
        runtime_classes, REGISTERED_CLASS_ORDER,
        "measurement host serves a different C-locale class table than the one \
         the position shape was registered against"
    );
    assert_eq!(
        runtime_maps, REGISTERED_MAP_ORDER,
        "measurement host serves a different C-locale map table than the one \
         the position shape was registered against"
    );

    let supplied_fl_identity = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path = CString::new(supplied_fl_identity.path.as_os_str().as_bytes())
        .expect("FrankenLibC SO path contains NUL");
    let handle = unsafe { libc::dlopen(fl_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "{}", dl_error("dlopen FrankenLibC SO"));

    let resolve = |name: &CStr| -> *mut c_void {
        let symbol = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(
            !symbol.is_null(),
            "{}",
            dl_error(&format!("dlsym {}", name.to_string_lossy()))
        );
        symbol
    };
    let fl_wctype_symbol = resolve(c"wctype");
    let fl_wctrans_symbol = resolve(c"wctrans");
    let fl_iswctype_symbol = resolve(c"iswctype");
    let fl_towctrans_symbol = resolve(c"towctrans");

    let fl = FlSymbols {
        wctype: unsafe { std::mem::transmute::<*mut c_void, NameFn>(fl_wctype_symbol) },
        wctrans: unsafe { std::mem::transmute::<*mut c_void, NameFn>(fl_wctrans_symbol) },
        iswctype: unsafe { std::mem::transmute::<*mut c_void, IswFn>(fl_iswctype_symbol) },
        towctrans: unsafe { std::mem::transmute::<*mut c_void, TowFn>(fl_towctrans_symbol) },
        wctype_address: fl_wctype_symbol.cast_const(),
        wctrans_address: fl_wctrans_symbol.cast_const(),
        iswctype_address: fl_iswctype_symbol.cast_const(),
        towctrans_address: fl_towctrans_symbol.cast_const(),
    };

    let host_wctype: NameFn = linked_host_wctype;
    let host_wctrans: NameFn = linked_host_wctrans;
    let host_iswctype: IswFn = linked_host_iswctype;
    let host_towctrans: TowFn = linked_host_towctrans;

    let host_identity = symbol_object(host_wctype as *const () as *const c_void)
        .expect("identify directly linked host wctype object");
    let fl_identity =
        symbol_object(fl.wctype_address).expect("identify loaded FrankenLibC wctype object");
    print_identity("INCUMBENT", &host_identity);
    print_identity("FL", &fl_identity);
    println!("INCUMBENT_LINKAGE direct_process_link symbols=wctype,wctrans,iswctype,towctrans");
    println!("FL_LINKAGE explicit_dlopen_local symbols=wctype,wctrans,iswctype,towctrans");

    assert!(
        host_identity
            .path
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(b"libc.so")),
        "incumbent wctype resolved to {}, not host libc",
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

    // Every one of the four symbol pairs must be distinct, or some row could
    // be measuring FrankenLibC against itself.
    for (symbol, host_address, fl_address) in [
        (
            "wctype",
            host_wctype as *const () as usize,
            fl.wctype_address as usize,
        ),
        (
            "wctrans",
            host_wctrans as *const () as usize,
            fl.wctrans_address as usize,
        ),
        (
            "iswctype",
            host_iswctype as *const () as usize,
            fl.iswctype_address as usize,
        ),
        (
            "towctrans",
            host_towctrans as *const () as usize,
            fl.towctrans_address as usize,
        ),
    ] {
        assert_ne!(
            host_address, fl_address,
            "{symbol}: both arms resolve to the same function address"
        );
        let served = symbol_object(fl_address as *const c_void)
            .unwrap_or_else(|error| panic!("identify FrankenLibC {symbol}: {error}"));
        assert_eq!(
            served.sha256, fl_identity.sha256,
            "{symbol} is not served by the supplied FrankenLibC object"
        );
        println!(
            "ARM_DISTINCT symbol={symbol} incumbent_address={host_address:#x} \
             fl_address={fl_address:#x}"
        );
    }

    let (recognition, class_composition, map_composition) = verify_conformance(
        host_wctype,
        host_wctrans,
        host_iswctype,
        host_towctrans,
        &fl,
    );
    println!(
        "WCTYPE_CONFORMANCE locale=C recognition_comparisons={recognition} \
         class_composition_comparisons={class_composition} \
         map_composition_comparisons={map_composition} \
         composition_domain=ascii_0x00_0x7f \
         descriptor_contract=opaque_per_library verdict=pass"
    );

    if config.verify_only {
        utf8_name_census(host_wctype, host_wctrans, &fl);
        println!("WCTYPE_VERIFY_ONLY verdict=pass");
        // Keep the comparison object resident until process exit. FrankenLibC
        // owns process-global/TLS state; unloading it after calling an
        // exported symbol is not part of the supported libc lifecycle.
        return;
    }

    let guard = HostWideBenchmarkGuard::new().unwrap_or_else(|error| {
        eprintln!("WCTYPE_BLOCKED phase=guard_init error={error}");
        std::process::exit(2);
    });
    let pre = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("WCTYPE_BLOCKED phase=pre_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", pre.contract_line("pre_measurement"));

    let mut results = Vec::new();

    // Group 1 — wctype(name): predicted large FrankenLibC win, monotone in
    // table position, unknown name slowest.
    let mut wctype_names: Vec<(String, i32, String)> = REGISTERED_CLASS_ORDER
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                (*name).to_owned(),
                index as i32,
                format!("recognised class at C-locale table index {index}"),
            )
        })
        .collect();
    wctype_names.push((
        "unknown".to_owned(),
        -1,
        "five-byte unrecognised name; glibc walks the whole table and cannot break early"
            .to_owned(),
    ));
    for (label, index, note) in wctype_names {
        let argument = if label == "unknown" {
            c_name(b"zzzzz")
        } else {
            c_name(label.as_bytes())
        };
        let pointer = argument.as_ptr();
        results.push(measure_case(
            "wctype",
            "wctype",
            label,
            note,
            index,
            || time_name(fl.wctype, pointer),
            || time_name(host_wctype, pointer),
        ));
    }

    // Group 2 — wctrans(name): satisfies (b) but fails (c). Predicted to be
    // strictly worse for FrankenLibC than every wctype case.
    let mut wctrans_names: Vec<(String, i32, String)> = REGISTERED_MAP_ORDER
        .iter()
        .enumerate()
        .map(|(index, name)| {
            (
                (*name).to_owned(),
                index as i32,
                format!(
                    "recognised map at C-locale table index {index}; FrankenLibC \
                     allocates to read the name, glibc walks at most two entries"
                ),
            )
        })
        .collect();
    wctrans_names.push((
        "unknown".to_owned(),
        -1,
        "unrecognised map name; glibc walks both entries and fails".to_owned(),
    ));
    for (label, index, note) in wctrans_names {
        let argument = if label == "unknown" {
            c_name(b"zzzzzzz")
        } else {
            c_name(label.as_bytes())
        };
        let pointer = argument.as_ptr();
        results.push(measure_case(
            "wctrans",
            "wctrans",
            label,
            note,
            index,
            || time_name(fl.wctrans, pointer),
            || time_name(host_wctrans, pointer),
        ));
    }

    // Group 3 — iswctype(wc, desc): fails (b). Each arm applies the descriptor
    // minted by its own library. ASCII only, the proved slice.
    for (class, wc, label) in [
        ("alpha", u32::from(b'a'), "alpha_hit"),
        ("digit", u32::from(b'7'), "digit_hit"),
        ("upper", u32::from(b'z'), "upper_miss"),
    ] {
        let name = c_name(class.as_bytes());
        let host_desc = unsafe { host_wctype(name.as_ptr()) };
        let fl_desc = unsafe { (fl.wctype)(name.as_ptr()) };
        assert!(host_desc != 0 && fl_desc != 0, "{class} must be recognised");
        let fl_iswctype = fl.iswctype;
        results.push(measure_case(
            "iswctype",
            "iswctype",
            label.to_owned(),
            format!(
                "class {class} applied to U+{wc:04X}; glibc is a branchless trie \
                 probe with no calls and no loop"
            ),
            -1,
            move || time_isw(fl_iswctype, wc, fl_desc),
            move || time_isw(host_iswctype, wc, host_desc),
        ));
    }

    // Group 4 — towctrans(wc, desc): the map-side companion to group 3.
    for (map, wc, label) in [
        ("toupper", u32::from(b'a'), "toupper_hit"),
        ("tolower", u32::from(b'A'), "tolower_hit"),
    ] {
        let name = c_name(map.as_bytes());
        let host_desc = unsafe { host_wctrans(name.as_ptr()) };
        let fl_desc = unsafe { (fl.wctrans)(name.as_ptr()) };
        assert!(host_desc != 0 && fl_desc != 0, "{map} must be recognised");
        let fl_towctrans = fl.towctrans;
        results.push(measure_case(
            "towctrans",
            "towctrans",
            label.to_owned(),
            format!("map {map} applied to U+{wc:04X}; descriptor already resolved"),
            -1,
            move || time_tow(fl_towctrans, wc, fl_desc),
            move || time_tow(host_towctrans, wc, host_desc),
        ));
    }

    let post = guard.check_quiet().unwrap_or_else(|error| {
        eprintln!("WCTYPE_BLOCKED phase=post_measurement error={error}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));

    for result in &results {
        result.print(&host_identity.path);
    }

    let verdict = adjudicate(&results);
    println!(
        "WCTYPE_PREDICTION verdict={} wctype_all_faster={} shape_endpoints={} \
         shape_unknown_slowest={} shape_rho={:.4} shape_monotone={} \
         shape_fl_flat={} fl_flat_ratio={:.4} iswctype_no_large_win={} \
         best_iswctype_ratio={:.6} wctrans_worse_than_wctype={} \
         worst_wctype_ratio={:.6} best_wctrans_ratio={:.6} \
         wctrans_not_a_win={} xdigit_below_trend={}",
        verdict.verdict,
        verdict.wctype_all_faster,
        verdict.shape_endpoints,
        verdict.shape_unknown_slowest,
        verdict.shape_rho,
        verdict.shape_monotone,
        verdict.shape_fl_flat,
        verdict.fl_flat_ratio,
        verdict.iswctype_no_large_win,
        verdict.best_iswctype_ratio,
        verdict.wctrans_worse_than_wctype,
        verdict.worst_wctype_ratio,
        verdict.best_wctrans_ratio,
        verdict.wctrans_not_a_win,
        verdict.xdigit_below_trend,
    );

    // Registered observation, taken only after every measurement is complete
    // so the locale change cannot touch a timing row.
    utf8_name_census(host_wctype, host_wctrans, &fl);

    // Keep the comparison object resident until process exit; see the
    // verify-only path above.
    if verdict.verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}
