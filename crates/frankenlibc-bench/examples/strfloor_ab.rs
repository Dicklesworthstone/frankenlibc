//! Is the fixed per-call floor on string-taking FrankenLibC entry points the
//! membrane bounds lookup, or something else? Measured against live glibc.
//!
//! WHY THIS RUN EXISTS. The `wctype` mechanism test (ledger 2026-07-30) measured
//! a flat ~11.2 ns floor on `wctype` against a glibc walk that starts at 5.8 ns,
//! and named `bounded_cstr_bytes` -> `known_remaining` as the STRUCTURAL SUSPECT
//! while explicitly recording that the attribution was NOT isolated. This run
//! isolates it, and it does so WITHOUT editing library source, so the thing
//! measured is the deployed object.
//!
//! THE LEVER: BUFFER PROVENANCE. `known_remaining` is
//! `bump_mmap_remaining` -> `segment_remaining` -> `fallback_remaining`, and
//! every one of those is address-keyed:
//!   * `bump_mmap_remaining` early-outs on an atomic flag;
//!   * `segment_remaining` looks the address up in the segment table;
//!   * `fallback_remaining` early-outs when the address is outside
//!     [`FALLBACK_ALLOC_MIN_ADDR`, `FALLBACK_ALLOC_MAX_ADDR`], but when the
//!     address IS in range it takes a LOCK and probes up to 1024 slots.
//! So if that chain is the floor, the SAME function on the SAME bytes must cost
//! different amounts depending only on where the buffer came from. If it is not
//! the floor, provenance cannot matter.
//!
//! DISCRIMINATING PAIR. Two string-taking exported symbols that differ in
//! exactly this respect:
//!   * `wctype` reads its argument with `bounded_cstr_bytes`, which calls
//!     `known_remaining` unconditionally. => PREDICT provenance-SENSITIVE.
//!   * `strtol` carries the deployed `stdlib_membrane_fastpath` bypass, which
//!     skips `decide`/`known_remaining` entirely. => PREDICT provenance-INSENSITIVE.
//! Opposite predictions for two symbols in one invocation, so "provenance
//! matters" cannot be a property of the harness.
//!
//! THE BUILT-IN CONTROL, and it is the load-bearing one. Buffers of different
//! provenance sit at different addresses, so they differ in cache set, page,
//! and TLB behaviour REGARDLESS of any registry. glibc has no allocation
//! registry, so glibc's own spread across the same four buffers measures
//! exactly that placement artifact. The registered discriminator is therefore
//! NOT "FrankenLibC varies" but "FrankenLibC varies MORE THAN GLIBC DOES ON THE
//! SAME BUFFERS".
//!
//! PRE-REGISTERED:
//!   P1  fl `wctype` provenance spread (max/min over the four buffers) exceeds
//!       glibc `wctype` provenance spread by at least 2x.
//!   P2  fl `strtol` provenance spread does NOT exceed glibc `strtol` spread by
//!       2x — the bypass means there is no registry cost to expose.
//!   P3  every row carries an fl/glibc incumbent ratio, because a self-speedup
//!       is maintenance and only an incumbent ratio is a campaign result.
//! P1 failing REFUTES `known_remaining` as the `wctype` floor term and obliges
//! a correction to the 2026-07-30 ledger row, which named it as the suspect.
//!
//! Contract: live glibc linked directly and called in the same invocation as
//! the strict FrankenLibC object loaded by explicit `dlopen`; benchmark ELF and
//! both serving objects self-report SHA-256 from inside the process; every arm
//! pair asserted to distinct addresses and distinct serving objects;
//! conformance precedes timing; per-arm A/A controls on every row; corrected
//! null gate (effect CI excludes 1.0, effect deviation exceeds 2x the larger
//! null half-width, each null MEDIAN within 2% of 1.0); ACTUAL OBSERVED thread
//! count reported, not the requested one; CV telemetry only.

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_long, c_ulong, c_void};
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
/// Registered in advance: how much more FrankenLibC must vary across buffer
/// provenance than glibc does on the same buffers before the variation is
/// attributed to the registry rather than to memory placement.
const PROVENANCE_FACTOR: f64 = 2.0;

type WctypeFn = unsafe extern "C" fn(*const c_char) -> c_ulong;
type StrtolFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char, c_int) -> c_long;
type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;

unsafe extern "C" {
    #[link_name = "wctype"]
    fn linked_host_wctype(name: *const c_char) -> c_ulong;
    #[link_name = "strtol"]
    fn linked_host_strtol(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_long;
    #[link_name = "setlocale"]
    fn linked_host_setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}

/// Static storage, so one of the four buffers lives in the object's own data
/// segment rather than on any heap or stack.
static mut STATIC_WCTYPE_BUF: [u8; 16] = *b"alnum\0\0\0\0\0\0\0\0\0\0\0";
static mut STATIC_STRTOL_BUF: [u8; 16] = *b"12345\0\0\0\0\0\0\0\0\0\0\0";

struct Config {
    fl_so: PathBuf,
    verify_only: bool,
}

#[derive(Debug)]
struct ObjectIdentity {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Debug)]
struct CaseResult {
    symbol: &'static str,
    provenance: &'static str,
    fl_median_ns: f64,
    glibc_median_ns: f64,
    effect_median: f64,
    effect_low: f64,
    effect_high: f64,
    effect_cv_pct: f64,
    fl_null_median: f64,
    fl_null_low: f64,
    fl_null_high: f64,
    fl_null_holds: bool,
    glibc_null_median: f64,
    glibc_null_low: f64,
    glibc_null_high: f64,
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

    fn print(&self, host_path: &Path, threads_observed: usize) {
        println!(
            "STRFLOOR symbol={} provenance={} host={} threads_observed={} \
             samples={} reps_per_arm={} fl_median_ns={:.3} glibc_median_ns={:.3}",
            self.symbol,
            self.provenance,
            host_path.display(),
            threads_observed,
            SAMPLES - WARMUPS,
            REPS,
            self.fl_median_ns,
            self.glibc_median_ns,
        );
        println!(
            "STRFLOOR_CONTRACT symbol={} provenance={} kind=null_fl_fl \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] \
             null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} null_holds={}",
            self.symbol,
            self.provenance,
            self.fl_null_median,
            self.fl_null_low,
            self.fl_null_high,
            self.fl_null_holds,
        );
        println!(
            "STRFLOOR_CONTRACT symbol={} provenance={} kind=null_glibc_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] \
             null_bias_tolerance={NULL_BIAS_TOLERANCE:.3} null_holds={}",
            self.symbol,
            self.provenance,
            self.glibc_null_median,
            self.glibc_null_low,
            self.glibc_null_high,
            self.glibc_null_holds,
        );
        println!(
            "STRFLOOR_CONTRACT symbol={} provenance={} kind=fl_glibc \
             ratio_median={:.6} ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} \
             null_half_width={:.6} clears_2x_null={} nulls_hold={} \
             comparison={} cv_role=telemetry_only gate=corrected_null_median_bias",
            self.symbol,
            self.provenance,
            self.effect_median,
            self.effect_low,
            self.effect_high,
            self.effect_cv_pct,
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
            panic!("unknown argument {arg:?}; usage: strfloor_ab --fl-so PATH [--verify-only]");
        }
    }
    Config {
        fl_so: fl_so.expect("missing --fl-so PATH"),
        verify_only,
    }
}

/// ACTUAL OBSERVED thread count for this process, read at measurement time.
/// Never the requested or assumed count.
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

// --------------------------------------------------------------------------
// Statistics — identical to the wctype/rpmatch harnesses, corrected null gate.
// --------------------------------------------------------------------------

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

// --------------------------------------------------------------------------
// Timed batches.
// --------------------------------------------------------------------------

#[inline(never)]
fn run_wctype_batch(function: WctypeFn, name: *const c_char) -> u64 {
    let mut accumulator = 0u64;
    for _ in 0..REPS {
        accumulator = accumulator.wrapping_add(unsafe { function(black_box(name)) } as u64);
    }
    black_box(accumulator)
}

#[inline(never)]
fn run_strtol_batch(function: StrtolFn, nptr: *const c_char) -> i64 {
    let mut accumulator = 0i64;
    let mut end: *mut c_char = std::ptr::null_mut();
    for _ in 0..REPS {
        accumulator =
            accumulator.wrapping_add(unsafe { function(black_box(nptr), &mut end, 10) } as i64);
    }
    black_box(end);
    black_box(accumulator)
}

fn time_wctype(function: WctypeFn, name: *const c_char) -> f64 {
    let started = Instant::now();
    black_box(run_wctype_batch(function, name));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

fn time_strtol(function: StrtolFn, nptr: *const c_char) -> f64 {
    let started = Instant::now();
    black_box(run_strtol_batch(function, nptr));
    started.elapsed().as_secs_f64() * 1_000_000_000.0 / REPS as f64
}

#[allow(clippy::too_many_arguments)]
fn measure_case<F, G>(
    symbol: &'static str,
    provenance: &'static str,
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
        let (mut fa, mut fb, mut ga, mut gb) = (0.0, 0.0, 0.0, 0.0);
        let (mut effect_fl, mut effect_glibc) = (0.0, 0.0);
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
        .map(|(f, g)| f / g)
        .collect::<Vec<_>>();
    let fl_null = fl_null_b
        .iter()
        .zip(&fl_null_a)
        .map(|(b, a)| b / a)
        .collect::<Vec<_>>();
    let glibc_null = glibc_null_b
        .iter()
        .zip(&glibc_null_a)
        .map(|(b, a)| b / a)
        .collect::<Vec<_>>();

    let effect_median = median(&effect);
    let (effect_low, effect_high) = bootstrap_median_ci95(&effect);
    let fl_null_median = median(&fl_null);
    let (fl_null_low, fl_null_high) = bootstrap_median_ci95(&fl_null);
    let glibc_null_median = median(&glibc_null);
    let (glibc_null_low, glibc_null_high) = bootstrap_median_ci95(&glibc_null);
    let fl_half = (fl_null_low - 1.0).abs().max((fl_null_high - 1.0).abs());
    let glibc_half = (glibc_null_low - 1.0)
        .abs()
        .max((glibc_null_high - 1.0).abs());
    let null_half_width = fl_half.max(glibc_half);
    let fl_null_holds = (fl_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let glibc_null_holds = (glibc_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let clears_2x_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let excludes_one = effect_high < 1.0 || effect_low > 1.0;
    let comparison = if !(fl_null_holds && glibc_null_holds) {
        "NULL_VIOLATED"
    } else if clears_2x_null && excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if clears_2x_null && excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    CaseResult {
        symbol,
        provenance,
        fl_median_ns: median(&fl_effect),
        glibc_median_ns: median(&glibc_effect),
        effect_median,
        effect_low,
        effect_high,
        effect_cv_pct: cv_pct(&effect),
        fl_null_median,
        fl_null_low,
        fl_null_high,
        fl_null_holds,
        glibc_null_median,
        glibc_null_low,
        glibc_null_high,
        glibc_null_holds,
        null_half_width,
        clears_2x_null,
        comparison,
    }
}

// --------------------------------------------------------------------------

fn spread(values: &[f64]) -> f64 {
    let max = values.iter().copied().fold(f64::MIN, f64::max);
    let min = values.iter().copied().fold(f64::MAX, f64::min);
    if min > 0.0 { max / min } else { f64::MAX }
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
        "HOST_IDENTITY hostname={} loadavg={} threads_observed={}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|v| v.trim().to_owned())
            .unwrap_or_else(|_| "unknown".to_owned()),
        std::fs::read_to_string("/proc/loadavg")
            .map(|v| v.split_whitespace().take(3).collect::<Vec<_>>().join(","))
            .unwrap_or_else(|_| "unknown".to_owned()),
        observed_threads(),
    );

    assert!(
        !unsafe { linked_host_setlocale(libc::LC_ALL, c"C".as_ptr()) }.is_null(),
        "host setlocale(LC_ALL, C) failed"
    );

    let supplied = sha256_file(&config.fl_so).expect("hash supplied FrankenLibC SO");
    let fl_path =
        CString::new(supplied.path.as_os_str().as_bytes()).expect("FrankenLibC SO path has NUL");
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
    let fl_wctype_sym = resolve(c"wctype");
    let fl_strtol_sym = resolve(c"strtol");
    let fl_malloc_sym = resolve(c"malloc");
    let fl_wctype: WctypeFn = unsafe { std::mem::transmute(fl_wctype_sym) };
    let fl_strtol: StrtolFn = unsafe { std::mem::transmute(fl_strtol_sym) };
    let fl_malloc: MallocFn = unsafe { std::mem::transmute(fl_malloc_sym) };

    let host_identity = symbol_object(linked_host_wctype as *const () as *const c_void)
        .expect("identify host wctype object");
    let fl_identity = symbol_object(fl_wctype_sym.cast_const()).expect("identify FrankenLibC");
    print_identity("INCUMBENT", &host_identity);
    print_identity("FL", &fl_identity);
    assert!(
        host_identity
            .path
            .file_name()
            .is_some_and(|n| n.as_bytes().starts_with(b"libc.so")),
        "incumbent resolved to {}, not host libc",
        host_identity.path.display()
    );
    assert_eq!(fl_identity.sha256, supplied.sha256, "loaded SO hash differs");
    assert_ne!(
        host_identity.sha256, fl_identity.sha256,
        "both arms are the same object"
    );
    for (symbol, host_addr, fl_addr) in [
        (
            "wctype",
            linked_host_wctype as *const () as usize,
            fl_wctype_sym as usize,
        ),
        (
            "strtol",
            linked_host_strtol as *const () as usize,
            fl_strtol_sym as usize,
        ),
    ] {
        assert_ne!(host_addr, fl_addr, "{symbol}: same function address");
        let served = symbol_object(fl_addr as *const c_void)
            .unwrap_or_else(|e| panic!("identify FrankenLibC {symbol}: {e}"));
        assert_eq!(
            served.sha256, fl_identity.sha256,
            "{symbol} not served by supplied object"
        );
        println!(
            "ARM_DISTINCT symbol={symbol} incumbent_address={host_addr:#x} fl_address={fl_addr:#x}"
        );
    }

    // ---- the four buffers: same bytes, four provenances --------------------
    let mut stack_wctype = *b"alnum\0\0\0\0\0\0\0\0\0\0\0";
    let mut stack_strtol = *b"12345\0\0\0\0\0\0\0\0\0\0\0";
    let glibc_wctype = CString::new("alnum").unwrap();
    let glibc_strtol = CString::new("12345").unwrap();
    let fl_wctype_buf = unsafe { fl_malloc(16) }.cast::<u8>();
    let fl_strtol_buf = unsafe { fl_malloc(16) }.cast::<u8>();
    assert!(
        !fl_wctype_buf.is_null() && !fl_strtol_buf.is_null(),
        "FrankenLibC malloc returned NULL; the fl-heap provenance arm cannot be built"
    );
    unsafe {
        std::ptr::copy_nonoverlapping(b"alnum\0".as_ptr(), fl_wctype_buf, 6);
        std::ptr::copy_nonoverlapping(b"12345\0".as_ptr(), fl_strtol_buf, 6);
    }
    let static_wctype = &raw mut STATIC_WCTYPE_BUF as *mut u8;
    let static_strtol = &raw mut STATIC_STRTOL_BUF as *mut u8;

    let wctype_bufs: [(&'static str, *const c_char); 4] = [
        ("stack", stack_wctype.as_mut_ptr().cast()),
        ("static", static_wctype.cast()),
        ("glibc_heap", glibc_wctype.as_ptr()),
        ("fl_heap", fl_wctype_buf.cast()),
    ];
    let strtol_bufs: [(&'static str, *const c_char); 4] = [
        ("stack", stack_strtol.as_mut_ptr().cast()),
        ("static", static_strtol.cast()),
        ("glibc_heap", glibc_strtol.as_ptr()),
        ("fl_heap", fl_strtol_buf.cast()),
    ];
    for (label, pointer) in wctype_bufs.iter().chain(&strtol_bufs) {
        println!("BUFFER_PROVENANCE label={label} address={:#x}", *pointer as usize);
    }

    // ---- conformance precedes timing --------------------------------------
    let mut comparisons = 0usize;
    for (label, pointer) in &wctype_bufs {
        let host = unsafe { linked_host_wctype(*pointer) };
        let fl = unsafe { fl_wctype(*pointer) };
        assert_eq!(
            host != 0,
            fl != 0,
            "wctype recognition mismatch for provenance {label}"
        );
        comparisons += 1;
    }
    for (label, pointer) in &strtol_bufs {
        let mut host_end: *mut c_char = std::ptr::null_mut();
        let mut fl_end: *mut c_char = std::ptr::null_mut();
        let host = unsafe { linked_host_strtol(*pointer, &mut host_end, 10) };
        let fl = unsafe { fl_strtol(*pointer, &mut fl_end, 10) };
        assert_eq!(host, fl, "strtol value mismatch for provenance {label}");
        assert_eq!(
            host_end as usize - *pointer as usize,
            fl_end as usize - *pointer as usize,
            "strtol endptr offset mismatch for provenance {label}"
        );
        comparisons += 1;
    }
    // Broader strtol agreement so the timed input is not a lucky special case.
    for value in [
        "0", "-1", "42", "12345", "  77", "+9", "0x1f", "999999999", "-2147483648",
        "9223372036854775807", "abc", "", "  ", "12abc", "-0",
    ] {
        for base in [0, 8, 10, 16] {
            let input = CString::new(value).unwrap();
            let mut host_end: *mut c_char = std::ptr::null_mut();
            let mut fl_end: *mut c_char = std::ptr::null_mut();
            let host = unsafe { linked_host_strtol(input.as_ptr(), &mut host_end, base) };
            let fl = unsafe { fl_strtol(input.as_ptr(), &mut fl_end, base) };
            assert_eq!(host, fl, "strtol value mismatch for {value:?} base {base}");
            assert_eq!(
                host_end as usize - input.as_ptr() as usize,
                fl_end as usize - input.as_ptr() as usize,
                "strtol endptr mismatch for {value:?} base {base}"
            );
            comparisons += 1;
        }
    }
    println!(
        "STRFLOOR_CONFORMANCE locale=C comparisons={comparisons} \
         provenances=stack,static,glibc_heap,fl_heap verdict=pass"
    );

    if config.verify_only {
        println!("STRFLOOR_VERIFY_ONLY verdict=pass");
        return;
    }

    let guard = HostWideBenchmarkGuard::new().unwrap_or_else(|e| {
        eprintln!("STRFLOOR_BLOCKED phase=guard_init error={e}");
        std::process::exit(2);
    });
    let pre = guard.check_quiet().unwrap_or_else(|e| {
        eprintln!("STRFLOOR_BLOCKED phase=pre_measurement error={e}");
        std::process::exit(2);
    });
    println!("{}", pre.contract_line("pre_measurement"));
    let threads_observed = observed_threads();

    let mut results = Vec::new();
    for (label, pointer) in wctype_bufs {
        results.push(measure_case(
            "wctype",
            label,
            || time_wctype(fl_wctype, pointer),
            || time_wctype(linked_host_wctype, pointer),
        ));
    }
    for (label, pointer) in strtol_bufs {
        results.push(measure_case(
            "strtol",
            label,
            || time_strtol(fl_strtol, pointer),
            || time_strtol(linked_host_strtol, pointer),
        ));
    }

    let post = guard.check_quiet().unwrap_or_else(|e| {
        eprintln!("STRFLOOR_BLOCKED phase=post_measurement error={e}");
        std::process::exit(2);
    });
    println!("{}", post.contract_line("post_measurement"));

    for result in &results {
        result.print(&host_identity.path, threads_observed);
    }

    let by = |symbol: &str, pick: fn(&CaseResult) -> f64| -> Vec<f64> {
        results
            .iter()
            .filter(|r| r.symbol == symbol)
            .map(pick)
            .collect()
    };
    let wctype_fl_spread = spread(&by("wctype", |r| r.fl_median_ns));
    let wctype_glibc_spread = spread(&by("wctype", |r| r.glibc_median_ns));
    let strtol_fl_spread = spread(&by("strtol", |r| r.fl_median_ns));
    let strtol_glibc_spread = spread(&by("strtol", |r| r.glibc_median_ns));

    let all_decidable = results.iter().all(CaseResult::decidable);
    let p1 = wctype_fl_spread > PROVENANCE_FACTOR * wctype_glibc_spread;
    let p2 = strtol_fl_spread <= PROVENANCE_FACTOR * strtol_glibc_spread;
    let verdict = if !all_decidable {
        "INCOMPLETE"
    } else if p1 && p2 {
        "CONFIRMED"
    } else {
        "REFUTED"
    };
    println!(
        "STRFLOOR_PREDICTION verdict={verdict} p1_wctype_provenance_sensitive={p1} \
         p2_strtol_provenance_insensitive={p2} \
         wctype_fl_spread={wctype_fl_spread:.4} wctype_glibc_spread={wctype_glibc_spread:.4} \
         strtol_fl_spread={strtol_fl_spread:.4} strtol_glibc_spread={strtol_glibc_spread:.4} \
         provenance_factor={PROVENANCE_FACTOR:.1} threads_observed={threads_observed}"
    );

    if verdict == "INCOMPLETE" {
        std::process::exit(2);
    }
}
