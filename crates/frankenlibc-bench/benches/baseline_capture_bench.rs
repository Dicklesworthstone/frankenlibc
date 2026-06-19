//! Baseline performance capture for implemented symbol families (bd-3h1u.1).
//!
//! Captures p50/p95/p99 latencies for ctype, math, stdlib, and errno families.
//! Complements existing benches (string_bench, malloc_bench, stdio_bench,
//! mutex_bench, condvar_bench) to achieve coverage across all major families.

use std::cell::RefCell;
use std::ffi::CStr;
use std::hint::black_box;
use std::os::raw::{c_char, c_int};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime};

#[derive(Default)]
struct BenchStats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl BenchStats {
    fn record(&mut self, iters: u64, dur: Duration) {
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, mode_label: &str, bench_label: &str, symbol: &str) {
        let mut samples = self.samples_ns_per_op.clone();
        if samples.is_empty() {
            return;
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p50 = percentile_sorted(&samples, 0.50);
        let p95 = percentile_sorted(&samples, 0.95);
        let p99 = percentile_sorted(&samples, 0.99);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let throughput_ops_s = if self.total_ns == 0 {
            0.0
        } else {
            (self.total_iters as f64) / (self.total_ns as f64 / 1e9)
        };

        println!(
            "BASELINE_CAPTURE_BENCH mode={} bench={} symbol={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
            mode_label,
            bench_label,
            symbol,
            samples.len(),
            p50,
            p95,
            p99,
            mean,
            throughput_ops_s
        );
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn mode_label() -> &'static str {
    match std::env::var("FRANKENLIBC_MODE").ok().as_deref() {
        Some("hardened") => "hardened",
        Some("strict") => "strict",
        _ => "raw",
    }
}

fn bench_symbol<F>(
    group: &mut criterion::BenchmarkGroup<'_, WallTime>,
    mode: &'static str,
    bench_label: &str,
    symbol: &str,
    mut op: F,
) where
    F: FnMut(),
{
    let stats = RefCell::new(BenchStats::default());
    group.bench_function(BenchmarkId::new(bench_label, mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                op();
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    stats.borrow().report(mode, bench_label, symbol);
}

#[inline]
fn abi_isalpha(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::isalpha(i32::from(c)) }
}

#[inline]
fn abi_isdigit(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::isdigit(i32::from(c)) }
}

#[inline]
fn abi_isspace(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::isspace(i32::from(c)) }
}

#[inline]
fn abi_toupper(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::toupper(i32::from(c)) }
}

#[inline]
fn abi_atoi(input: &[u8]) -> i32 {
    // SAFETY: benchmark inputs are static NUL-terminated byte strings.
    unsafe { frankenlibc_abi::stdlib_abi::atoi(input.as_ptr().cast()) }
}

#[inline]
fn abi_errno_location() -> *mut i32 {
    // SAFETY: __errno_location returns the current thread's valid errno slot.
    unsafe { frankenlibc_abi::errno_abi::__errno_location() }
}

// ═══════════════════════════════════════════════════════════════════
// CTYPE FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_ctype_isalpha(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_isalpha");

    for _ in 0..10_000 {
        black_box(abi_isalpha(b'A'));
        black_box(abi_isalpha(b'5'));
    }

    bench_symbol(&mut group, mode, "isalpha_ascii_letter", "isalpha", || {
        black_box(abi_isalpha(black_box(b'A')));
    });
    bench_symbol(&mut group, mode, "isalpha_digit", "isalpha", || {
        black_box(abi_isalpha(black_box(b'5')));
    });

    group.finish();
}

fn bench_ctype_isdigit(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_isdigit");

    for _ in 0..10_000 {
        black_box(abi_isdigit(b'7'));
        black_box(abi_isdigit(b'z'));
    }

    bench_symbol(&mut group, mode, "isdigit_digit", "isdigit", || {
        black_box(abi_isdigit(black_box(b'7')));
    });
    bench_symbol(&mut group, mode, "isdigit_letter", "isdigit", || {
        black_box(abi_isdigit(black_box(b'z')));
    });

    group.finish();
}

fn bench_ctype_toupper(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_toupper");

    for _ in 0..10_000 {
        black_box(abi_toupper(b'a'));
        black_box(abi_toupper(b'A'));
    }

    bench_symbol(&mut group, mode, "toupper_lowercase", "toupper", || {
        black_box(abi_toupper(black_box(b'a')));
    });
    bench_symbol(&mut group, mode, "toupper_already_upper", "toupper", || {
        black_box(abi_toupper(black_box(b'A')));
    });

    group.finish();
}

fn bench_ctype_isspace(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_isspace");

    for _ in 0..10_000 {
        black_box(abi_isspace(b' '));
        black_box(abi_isspace(b'x'));
    }

    bench_symbol(&mut group, mode, "isspace_space", "isspace", || {
        black_box(abi_isspace(black_box(b' ')));
    });
    bench_symbol(&mut group, mode, "isspace_non_space", "isspace", || {
        black_box(abi_isspace(black_box(b'x')));
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// MATH FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_math_trig(c: &mut Criterion) {
    use frankenlibc_core::math::{cos, sin, tan};

    c.bench_function("math/sin/small", |b| {
        b.iter(|| black_box(sin(black_box(0.5))))
    });

    c.bench_function("math/cos/small", |b| {
        b.iter(|| black_box(cos(black_box(0.5))))
    });

    c.bench_function("math/tan/small", |b| {
        b.iter(|| black_box(tan(black_box(0.5))))
    });
}

fn bench_math_exp_log(c: &mut Criterion) {
    use frankenlibc_core::math::{exp, log};

    c.bench_function("math/exp/small", |b| {
        b.iter(|| black_box(exp(black_box(1.5))))
    });

    c.bench_function("math/log/small", |b| {
        b.iter(|| black_box(log(black_box(2.5))))
    });
}

fn bench_math_sqrt(c: &mut Criterion) {
    use frankenlibc_core::math::sqrt;

    c.bench_function("math/sqrt/integer", |b| {
        b.iter(|| black_box(sqrt(black_box(144.0))))
    });

    c.bench_function("math/sqrt/large", |b| {
        b.iter(|| black_box(sqrt(black_box(1e12))))
    });
}

fn bench_math_pow(c: &mut Criterion) {
    use frankenlibc_core::math::pow;

    c.bench_function("math/pow/integer_exp", |b| {
        b.iter(|| black_box(pow(black_box(2.0), black_box(10.0))))
    });

    c.bench_function("math/pow/fractional_exp", |b| {
        b.iter(|| black_box(pow(black_box(2.0), black_box(0.5))))
    });
}

// ═══════════════════════════════════════════════════════════════════
// STDLIB FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_stdlib_atoi(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("stdlib_atoi");

    for _ in 0..10_000 {
        black_box(abi_atoi(b"42\0"));
        black_box(abi_atoi(b"2147483647\0"));
        black_box(abi_atoi(b"-999\0"));
    }

    bench_symbol(&mut group, mode, "atoi_small", "atoi", || {
        black_box(abi_atoi(black_box(b"42\0")));
    });
    bench_symbol(&mut group, mode, "atoi_large", "atoi", || {
        black_box(abi_atoi(black_box(b"2147483647\0")));
    });
    bench_symbol(&mut group, mode, "atoi_negative", "atoi", || {
        black_box(abi_atoi(black_box(b"-999\0")));
    });

    group.finish();
}

fn bench_stdlib_abs(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("stdlib_abs");

    for _ in 0..10_000 {
        black_box(frankenlibc_abi::stdlib_abi::abs(42));
        black_box(frankenlibc_abi::stdlib_abi::abs(-42));
    }

    bench_symbol(&mut group, mode, "abs_positive", "abs", || {
        black_box(frankenlibc_abi::stdlib_abi::abs(black_box(42)));
    });
    bench_symbol(&mut group, mode, "abs_negative", "abs", || {
        black_box(frankenlibc_abi::stdlib_abi::abs(black_box(-42)));
    });

    group.finish();
}

#[inline(never)]
fn scan_getopt_short_bundle(argv: &[&[u8]], optspec: &[u8]) -> i32 {
    let (checksum, optind) = scan_getopt_short_bundle_codes(argv, optspec);
    checksum ^ optind as i32
}

#[inline(never)]
fn scan_getopt_short_bundle_codes(argv: &[&[u8]], optspec: &[u8]) -> (i32, usize) {
    use frankenlibc_core::getopt::{GetoptState, StepOutcome, step_short};

    let mut state = GetoptState::default();
    let mut checksum = 0i32;
    loop {
        match step_short(argv, optspec, &mut state) {
            StepOutcome::Done => break,
            StepOutcome::Found { code, .. } => {
                checksum = checksum.wrapping_mul(31).wrapping_add(code);
            }
            StepOutcome::LongRoute { arg } => {
                let bytes = argv[arg.argv_idx];
                let routed = bytes.get(arg.byte_offset).copied().unwrap_or_default();
                checksum = checksum.wrapping_mul(31).wrapping_add(i32::from(routed));
            }
        }
    }
    (checksum, state.optind)
}

#[inline(never)]
fn scan_getopt_short_bundle_glibc_comparable() -> i32 {
    let argv: [&[u8]; 6] = [b"prog", b"-ab", b"-cVALUE", b"-dVALUE", b"-ef", b"operand"];
    scan_getopt_short_bundle_codes(&argv, b"abc:d:ef").0
}

type HostGetoptFn = unsafe extern "C" fn(c_int, *const *mut c_char, *const c_char) -> c_int;

struct HostGetopt {
    getopt: HostGetoptFn,
    optarg: usize,
    opterr: usize,
    optind: usize,
    optopt: usize,
    process_optarg: usize,
    process_opterr: usize,
    process_optind: usize,
    process_optopt: usize,
}

fn host_getopt() -> &'static HostGetopt {
    static HOST_GETOPT: OnceLock<HostGetopt> = OnceLock::new();
    HOST_GETOPT.get_or_init(load_host_getopt)
}

fn load_host_getopt() -> HostGetopt {
    unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(
            !handle.is_null(),
            "failed to dlmopen host libc.so.6 in isolated namespace"
        );

        let getopt = libc::dlsym(handle, b"getopt\0".as_ptr().cast());
        assert!(!getopt.is_null(), "failed to resolve host glibc getopt");

        HostGetopt {
            getopt: std::mem::transmute::<*mut libc::c_void, HostGetoptFn>(getopt),
            optarg: dlsym_required(handle, b"optarg\0", "optarg") as usize,
            opterr: dlsym_required(handle, b"opterr\0", "opterr") as usize,
            optind: dlsym_required(handle, b"optind\0", "optind") as usize,
            optopt: dlsym_required(handle, b"optopt\0", "optopt") as usize,
            process_optarg: dlsym_optional(std::ptr::null_mut(), b"optarg\0") as usize,
            process_opterr: dlsym_optional(std::ptr::null_mut(), b"opterr\0") as usize,
            process_optind: dlsym_optional(std::ptr::null_mut(), b"optind\0") as usize,
            process_optopt: dlsym_optional(std::ptr::null_mut(), b"optopt\0") as usize,
        }
    }
}

unsafe fn dlsym_required(
    handle: *mut libc::c_void,
    symbol: &'static [u8],
    label: &str,
) -> *mut libc::c_void {
    let ptr = unsafe { libc::dlsym(handle, symbol.as_ptr().cast()) };
    assert!(
        !ptr.is_null(),
        "failed to resolve host glibc symbol {label}"
    );
    ptr
}

unsafe fn dlsym_optional(handle: *mut libc::c_void, symbol: &'static [u8]) -> *mut libc::c_void {
    unsafe { libc::dlsym(handle, symbol.as_ptr().cast()) }
}

unsafe fn store_optional_i32(ptr: usize, value: c_int) {
    if ptr != 0 {
        unsafe {
            *(ptr as *mut c_int) = value;
        }
    }
}

unsafe fn store_optional_ptr(ptr: usize, value: *mut c_char) {
    if ptr != 0 {
        unsafe {
            *(ptr as *mut *mut c_char) = value;
        }
    }
}

unsafe fn load_optional_i32(ptr: usize) -> Option<c_int> {
    if ptr == 0 {
        None
    } else {
        Some(unsafe { *(ptr as *mut c_int) })
    }
}

#[inline(never)]
fn scan_host_glibc_getopt_short_bundle() -> i32 {
    scan_host_glibc_getopt_short_bundle_state().0
}

#[inline(never)]
fn scan_host_glibc_getopt_short_bundle_state() -> (i32, c_int) {
    let host = host_getopt();
    let mut argv = [
        b"prog\0".as_ptr() as *mut c_char,
        b"-ab\0".as_ptr() as *mut c_char,
        b"-cVALUE\0".as_ptr() as *mut c_char,
        b"-dVALUE\0".as_ptr() as *mut c_char,
        b"-ef\0".as_ptr() as *mut c_char,
        b"operand\0".as_ptr() as *mut c_char,
        std::ptr::null_mut(),
    ];
    let argc = (argv.len() - 1) as c_int;
    let optspec = b"abc:d:ef\0";
    let mut checksum = 0i32;

    unsafe {
        *(host.optarg as *mut *mut c_char) = std::ptr::null_mut();
        *(host.opterr as *mut c_int) = 0;
        // GNU getopt uses optind=0 to reset both optind and its hidden scanner
        // state before a fresh argv pass. The benchmark process also links
        // frankenlibc_abi's exported opt* globals, so reset both libc's handle
        // symbols and the process-visible symbols to avoid interposition state.
        *(host.optind as *mut c_int) = 0;
        *(host.optopt as *mut c_int) = 0;
        store_optional_ptr(host.process_optarg, std::ptr::null_mut());
        store_optional_i32(host.process_opterr, 0);
        store_optional_i32(host.process_optind, 0);
        store_optional_i32(host.process_optopt, 0);

        loop {
            let code = (host.getopt)(argc, argv.as_mut_ptr(), optspec.as_ptr().cast());
            if code == -1 {
                break;
            }
            checksum = checksum.wrapping_mul(31).wrapping_add(code);
        }

        let libc_optind = *(host.optind as *mut c_int);
        let process_optind = load_optional_i32(host.process_optind).unwrap_or(0);
        (checksum, libc_optind.max(process_optind))
    }
}

fn bench_stdlib_getopt(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("stdlib_getopt");
    let argv: [&[u8]; 7] = [
        b"prog",
        b"-abc",
        b"-dVALUE",
        b"-W",
        b"color=auto",
        b"-ef",
        b"operand",
    ];
    let optspec = b"abc:d:efW;";

    for _ in 0..10_000 {
        black_box(scan_getopt_short_bundle(
            black_box(&argv),
            black_box(optspec),
        ));
    }

    bench_symbol(
        &mut group,
        mode,
        "getopt_short_bundle_typical",
        "getopt",
        || {
            black_box(scan_getopt_short_bundle(
                black_box(&argv),
                black_box(optspec),
            ));
        },
    );

    let fl_workload: [&[u8]; 6] = [b"prog", b"-ab", b"-cVALUE", b"-dVALUE", b"-ef", b"operand"];
    let (fl_checksum, fl_optind) = scan_getopt_short_bundle_codes(&fl_workload, b"abc:d:ef");
    let (glibc_checksum, glibc_optind) = scan_host_glibc_getopt_short_bundle_state();
    assert_eq!(
        fl_checksum, glibc_checksum,
        "FrankenLibC and host glibc getopt comparable workload diverged"
    );
    assert_eq!(
        fl_optind as c_int, glibc_optind,
        "FrankenLibC and host glibc getopt final optind diverged"
    );

    bench_symbol(
        &mut group,
        "frankenlibc_core",
        "getopt_short_bundle_glibc_comparable",
        "getopt",
        || {
            black_box(scan_getopt_short_bundle_glibc_comparable());
        },
    );
    bench_symbol(
        &mut group,
        "host_glibc",
        "getopt_short_bundle_glibc_comparable",
        "getopt",
        || {
            black_box(scan_host_glibc_getopt_short_bundle());
        },
    );

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// NSS / PASSWD FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

type HostGetpwnamFn = unsafe extern "C" fn(*const c_char) -> *mut libc::passwd;
type HostGetpwuidFn = unsafe extern "C" fn(libc::uid_t) -> *mut libc::passwd;

struct HostPasswd {
    getpwnam: HostGetpwnamFn,
    getpwuid: HostGetpwuidFn,
}

fn host_passwd() -> &'static HostPasswd {
    static HOST_PASSWD: OnceLock<HostPasswd> = OnceLock::new();
    HOST_PASSWD.get_or_init(load_host_passwd)
}

fn load_host_passwd() -> HostPasswd {
    unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(
            !handle.is_null(),
            "failed to dlmopen host libc.so.6 in isolated namespace"
        );

        let getpwnam = dlsym_required(handle, b"getpwnam\0", "getpwnam");
        let getpwuid = dlsym_required(handle, b"getpwuid\0", "getpwuid");
        HostPasswd {
            getpwnam: std::mem::transmute::<*mut libc::c_void, HostGetpwnamFn>(getpwnam),
            getpwuid: std::mem::transmute::<*mut libc::c_void, HostGetpwuidFn>(getpwuid),
        }
    }
}

fn passwd_checksum(entry: *mut libc::passwd) -> usize {
    assert!(!entry.is_null(), "passwd lookup returned NULL");
    unsafe {
        // SAFETY: callers pass a non-NULL pointer returned by getpwnam/getpwuid.
        let pw = &*entry;
        (pw.pw_uid as usize)
            .wrapping_mul(1_000_003)
            .wrapping_add(pw.pw_gid as usize)
            .wrapping_mul(257)
            .wrapping_add(cstr_first_byte(pw.pw_name))
            .wrapping_mul(257)
            .wrapping_add(cstr_first_byte(pw.pw_dir))
            .wrapping_mul(257)
            .wrapping_add(cstr_first_byte(pw.pw_shell))
    }
}

unsafe fn cstr_first_byte(ptr: *const c_char) -> usize {
    if ptr.is_null() {
        0
    } else {
        // SAFETY: passwd fields from libc are NUL-terminated strings.
        unsafe { *ptr.cast::<u8>() as usize }
    }
}

unsafe fn cstr_bytes(ptr: *const c_char) -> Vec<u8> {
    if ptr.is_null() {
        Vec::new()
    } else {
        // SAFETY: passwd fields from libc are NUL-terminated strings.
        unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() }
    }
}

fn assert_passwd_entries_match(
    frankenlibc: *mut libc::passwd,
    host_glibc: *mut libc::passwd,
    label: &str,
) {
    assert!(
        !frankenlibc.is_null(),
        "FrankenLibC passwd lookup returned NULL for {label}"
    );
    assert!(
        !host_glibc.is_null(),
        "host glibc passwd lookup returned NULL for {label}"
    );
    unsafe {
        // SAFETY: both pointers were checked non-NULL and are live until the
        // next passwd lookup in the same libc namespace.
        let fl = &*frankenlibc;
        let glibc = &*host_glibc;
        assert_eq!(fl.pw_uid, glibc.pw_uid, "passwd uid mismatch for {label}");
        assert_eq!(fl.pw_gid, glibc.pw_gid, "passwd gid mismatch for {label}");
        assert_eq!(
            cstr_bytes(fl.pw_name),
            cstr_bytes(glibc.pw_name),
            "passwd name mismatch for {label}"
        );
        assert_eq!(
            cstr_bytes(fl.pw_dir),
            cstr_bytes(glibc.pw_dir),
            "passwd dir mismatch for {label}"
        );
        assert_eq!(
            cstr_bytes(fl.pw_shell),
            cstr_bytes(glibc.pw_shell),
            "passwd shell mismatch for {label}"
        );
    }
}

#[inline(never)]
fn frankenlibc_getpwnam_root() -> usize {
    let entry = unsafe {
        // SAFETY: benchmark input is a static NUL-terminated C string.
        frankenlibc_abi::pwd_abi::getpwnam(b"root\0".as_ptr().cast())
    };
    passwd_checksum(entry)
}

#[inline(never)]
fn host_glibc_getpwnam_root() -> usize {
    let host = host_passwd();
    let entry = unsafe {
        // SAFETY: benchmark input is a static NUL-terminated C string.
        (host.getpwnam)(b"root\0".as_ptr().cast())
    };
    passwd_checksum(entry)
}

#[inline(never)]
fn frankenlibc_getpwuid_0() -> usize {
    let entry = unsafe {
        // SAFETY: uid 0 is a valid getpwuid input.
        frankenlibc_abi::pwd_abi::getpwuid(0)
    };
    passwd_checksum(entry)
}

#[inline(never)]
fn host_glibc_getpwuid_0() -> usize {
    let host = host_passwd();
    let entry = unsafe {
        // SAFETY: uid 0 is a valid getpwuid input.
        (host.getpwuid)(0)
    };
    passwd_checksum(entry)
}

fn bench_nss_passwd_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("nss_passwd_lookup");
    let host = host_passwd();

    unsafe {
        // SAFETY: benchmark inputs are static valid getpwnam/getpwuid inputs.
        assert_passwd_entries_match(
            frankenlibc_abi::pwd_abi::getpwnam(b"root\0".as_ptr().cast()),
            (host.getpwnam)(b"root\0".as_ptr().cast()),
            "getpwnam(root)",
        );
        assert_passwd_entries_match(
            frankenlibc_abi::pwd_abi::getpwuid(0),
            (host.getpwuid)(0),
            "getpwuid(0)",
        );
    }

    for _ in 0..1_000 {
        black_box(frankenlibc_getpwnam_root());
        black_box(host_glibc_getpwnam_root());
        black_box(frankenlibc_getpwuid_0());
        black_box(host_glibc_getpwuid_0());
    }

    bench_symbol(
        &mut group,
        "frankenlibc_abi",
        "getpwnam_root_glibc_comparable",
        "getpwnam",
        || {
            black_box(frankenlibc_getpwnam_root());
        },
    );
    bench_symbol(
        &mut group,
        "host_glibc",
        "getpwnam_root_glibc_comparable",
        "getpwnam",
        || {
            black_box(host_glibc_getpwnam_root());
        },
    );
    bench_symbol(
        &mut group,
        "frankenlibc_abi",
        "getpwuid_0_glibc_comparable",
        "getpwuid",
        || {
            black_box(frankenlibc_getpwuid_0());
        },
    );
    bench_symbol(
        &mut group,
        "host_glibc",
        "getpwuid_0_glibc_comparable",
        "getpwuid",
        || {
            black_box(host_glibc_getpwuid_0());
        },
    );

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// ERRNO FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_errno_location(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("errno_location");

    // SAFETY: returned pointer is valid for the current thread.
    unsafe { *abi_errno_location() = 0 };
    for _ in 0..10_000 {
        black_box(abi_errno_location());
    }

    bench_symbol(
        &mut group,
        mode,
        "errno_location",
        "__errno_location",
        || {
            black_box(abi_errno_location());
        },
    );

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// STRING FAMILY — additional sizes not in string_bench.rs
// ═══════════════════════════════════════════════════════════════════

fn bench_strlen_varied(c: &mut Criterion) {
    use frankenlibc_core::string::strlen;

    for len in [1, 8, 32, 128, 512] {
        let mut s = vec![b'x'; len];
        s.push(0);
        let label = format!("string/strlen/{len}");
        c.bench_function(&label, |b| {
            b.iter(|| black_box(strlen(black_box(s.as_slice()))))
        });
    }
}

fn bench_strcmp_varied(c: &mut Criterion) {
    use frankenlibc_core::string::strcmp;

    for len in [4, 32, 256] {
        let mut a = vec![b'a'; len];
        a.push(0);
        let b_equal = a.clone();
        let label_eq = format!("string/strcmp/equal_{len}");
        c.bench_function(&label_eq, |bench| {
            bench.iter(|| {
                black_box(strcmp(
                    black_box(a.as_slice()),
                    black_box(b_equal.as_slice()),
                ))
            })
        });

        // Differ at last byte
        let mut b_diff = a.clone();
        b_diff[len - 1] = b'b';
        let label_diff = format!("string/strcmp/differ_last_{len}");
        c.bench_function(&label_diff, |bench| {
            bench.iter(|| {
                black_box(strcmp(
                    black_box(a.as_slice()),
                    black_box(b_diff.as_slice()),
                ))
            })
        });
    }
}

criterion_group!(
    name = ctype_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_ctype_isalpha, bench_ctype_isdigit, bench_ctype_toupper, bench_ctype_isspace
);

criterion_group!(
    name = math_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_math_trig, bench_math_exp_log, bench_math_sqrt, bench_math_pow
);

criterion_group!(
    name = stdlib_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_stdlib_atoi, bench_stdlib_abs, bench_stdlib_getopt
);

criterion_group!(
    name = nss_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_nss_passwd_lookup
);

criterion_group!(
    name = errno_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_errno_location
);

criterion_group!(
    name = string_extended_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_strlen_varied, bench_strcmp_varied
);

criterion_main!(
    ctype_benches,
    math_benches,
    stdlib_benches,
    nss_benches,
    errno_benches,
    string_extended_benches,
);
