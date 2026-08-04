//! Head-to-head `calloc` benchmark: FrankenLibC vs a pristine host glibc.
//!
//! Campaign target bd-7ak6cm: fl `calloc` historically did an unconditional
//! `write_bytes(0, total)` over every allocation, while glibc's `calloc` skips
//! the memset for large blocks served fresh from `mmap(MAP_ANONYMOUS)` (already
//! kernel-zeroed). The lever routes fl `calloc` through `alloc_zeroed`, which
//! the system allocator services via libc `calloc`, inheriting the same
//! mmap-zeroed skip. This bench measures the alloc+free cycle cost at a range of
//! sizes so the large (mmap-served, >128K) regime where the redundant memset
//! dominates is visible head-to-head.
//!
//! glibc baseline is loaded through `dlmopen(LM_ID_NEWLM, "libc.so.6")` so that
//! fl's `no_mangle` `calloc`/`free` (active in release builds) do not interpose
//! the host symbols — each allocator is exercised with its own paired
//! `calloc`/`free` so pointers never cross allocators.

use std::ffi::c_void;
use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group};
use sha2::{Digest, Sha256};

type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);

struct HostAllocator {
    calloc: CallocFn,
    realloc: ReallocFn,
    free: FreeFn,
}

const PAIRED_ROUNDS: usize = 21;
const BOOTSTRAP_RESAMPLES: usize = 4096;
const MIN_ARM_SAMPLE_NS: u128 = 2_000_000;
const MAX_PAIRED_ITERS: u64 = 1 << 20;

/// SHA-256 of this executable, reported from inside the measured process.
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

#[derive(Debug)]
struct PairedStats {
    p50_a_ns: f64,
    p50_b_ns: f64,
    ratio_p50: f64,
    ratio_cv_pct: f64,
    ratio_mad: f64,
    ratio_ci95_low: f64,
    ratio_ci95_high: f64,
    checksum: u64,
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn coefficient_of_variation_pct(values: &[f64]) -> f64 {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if values.len() < 2 || mean == 0.0 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / (values.len() - 1) as f64;
    100.0 * variance.sqrt() / mean
}

fn median_absolute_deviation(values: &[f64], center: f64) -> f64 {
    let deviations = values
        .iter()
        .map(|value| (value - center).abs())
        .collect::<Vec<_>>();
    median(&deviations)
}

fn bootstrap_median_ci95(values: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ values.len() as u64;
    let mut resampled_medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; values.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = values[(state as usize) % values.len()];
        }
        resampled_medians.push(median(&resample));
    }
    resampled_medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (resampled_medians[low], resampled_medians[high])
}

fn time_arm(iters: u64, arm: &mut impl FnMut() -> u64) -> (f64, u64) {
    let start = Instant::now();
    let mut checksum = 0u64;
    for iteration in 0..iters {
        checksum =
            checksum.rotate_left(11) ^ black_box(arm()) ^ iteration.wrapping_mul(0x9e37_79b9);
    }
    (
        start.elapsed().as_nanos() as f64 / iters.max(1) as f64,
        black_box(checksum),
    )
}

/// Time both arms back-to-back in every round, alternating their order.
///
/// The decision statistic is the median of the per-round A/B ratios. CV is
/// descriptive provenance only; the bootstrap interval on the median is the
/// acceptance instrument.
fn paired(
    rounds: usize,
    iters: u64,
    mut arm_a: impl FnMut() -> u64,
    mut arm_b: impl FnMut() -> u64,
) -> PairedStats {
    let mut samples_a = Vec::with_capacity(rounds);
    let mut samples_b = Vec::with_capacity(rounds);
    let mut ratios = Vec::with_capacity(rounds);
    let mut checksum = 0u64;

    for round in 0..rounds {
        let ((elapsed_a, checksum_a), (elapsed_b, checksum_b)) = if round.is_multiple_of(2) {
            (time_arm(iters, &mut arm_a), time_arm(iters, &mut arm_b))
        } else {
            let b = time_arm(iters, &mut arm_b);
            let a = time_arm(iters, &mut arm_a);
            (a, b)
        };
        samples_a.push(elapsed_a);
        samples_b.push(elapsed_b);
        ratios.push(elapsed_a / elapsed_b.max(f64::MIN_POSITIVE));
        checksum = checksum.rotate_left(7) ^ checksum_a ^ checksum_b.rotate_left(1);
    }

    let ratio_p50 = median(&ratios);
    let (ratio_ci95_low, ratio_ci95_high) = bootstrap_median_ci95(&ratios);
    PairedStats {
        p50_a_ns: median(&samples_a),
        p50_b_ns: median(&samples_b),
        ratio_p50,
        ratio_cv_pct: coefficient_of_variation_pct(&ratios),
        ratio_mad: median_absolute_deviation(&ratios, ratio_p50),
        ratio_ci95_low,
        ratio_ci95_high,
        checksum: black_box(checksum),
    }
}

fn claim_clears_null_with_2x_margin(null: &PairedStats, claim_ratio: f64) -> bool {
    let null_half_width = (1.0 - null.ratio_ci95_low)
        .abs()
        .max((null.ratio_ci95_high - 1.0).abs());
    (claim_ratio - 1.0).abs() > 2.0 * null_half_width
}

fn report_pair(kind: &str, size: usize, iters: u64, stats: &PairedStats) {
    println!(
        "CALLOC_BENCH_CONTRACT kind={kind} size={size} rounds={PAIRED_ROUNDS} iters={iters} \
         p50_a_ns={:.3} p50_b_ns={:.3} ratio_median={:.6} \
         ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} ratio_mad={:.6} checksum={}",
        stats.p50_a_ns,
        stats.p50_b_ns,
        stats.ratio_p50,
        stats.ratio_ci95_low,
        stats.ratio_ci95_high,
        stats.ratio_cv_pct,
        stats.ratio_mad,
        stats.checksum,
    );
}

/// Resolve a pristine host glibc allocator in an isolated link
/// namespace so fl's interposing `no_mangle` symbols are bypassed.
fn host_allocator() -> &'static HostAllocator {
    static HOST: OnceLock<HostAllocator> = OnceLock::new();
    HOST.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(
            !handle.is_null(),
            "failed to dlmopen host libc.so.6 in isolated namespace"
        );
        let calloc = libc::dlsym(handle, b"calloc\0".as_ptr().cast());
        let realloc = libc::dlsym(handle, b"realloc\0".as_ptr().cast());
        let free = libc::dlsym(handle, b"free\0".as_ptr().cast());
        assert!(!calloc.is_null(), "failed to resolve host glibc calloc");
        assert!(!realloc.is_null(), "failed to resolve host glibc realloc");
        assert!(!free.is_null(), "failed to resolve host glibc free");
        HostAllocator {
            calloc: std::mem::transmute::<*mut libc::c_void, CallocFn>(calloc),
            realloc: std::mem::transmute::<*mut libc::c_void, ReallocFn>(realloc),
            free: std::mem::transmute::<*mut libc::c_void, FreeFn>(free),
        }
    })
}

#[derive(Default)]
struct Stats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl Stats {
    fn record(&mut self, iters: u64, dur: Duration) {
        if iters == 0 {
            return;
        }
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, impl_label: &str, size: usize) {
        let mut s = self.samples_ns_per_op.clone();
        if s.is_empty() {
            return;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx =
            |pct: f64| -> usize { ((s.len().saturating_sub(1)) as f64 * pct).round() as usize };
        let p50 = s[idx(0.50)];
        let p95 = s[idx(0.95)];
        let p99 = s[idx(0.99)];
        let mean = self.total_ns as f64 / self.total_iters.max(1) as f64;
        let throughput = if self.total_ns == 0 {
            0.0
        } else {
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };
        println!(
            "CALLOC_BENCH impl={impl_label} size={size} samples={} p50_ns_op={p50:.3} \
             p95_ns_op={p95:.3} p99_ns_op={p99:.3} mean_ns_op={mean:.3} throughput_ops_s={throughput:.3}",
            s.len(),
        );
    }

    fn report_workload(&self, impl_label: &str, workload: &str) {
        let mut s = self.samples_ns_per_op.clone();
        if s.is_empty() {
            return;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = percentile_sorted(&s, 0.50);
        let p95 = percentile_sorted(&s, 0.95);
        let p99 = percentile_sorted(&s, 0.99);
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        let throughput = if self.total_ns == 0 {
            0.0
        } else {
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };
        println!(
            "REALLOC_BENCH impl={impl_label} workload={workload} samples={} p50_ns_op={p50:.3} \
             p95_ns_op={p95:.3} p99_ns_op={p99:.3} mean_ns_op={mean:.3} throughput_ops_s={throughput:.3}",
            s.len(),
        );
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = p * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }
}

/// Sizes span the small (arena/sbrk-served, calloc memsets either way) and the
/// large (>128K mmap-threshold, kernel-zeroed, where the redundant memset is the
/// whole cost) regimes.
const SIZES: &[usize] = &[16, 256, 4096, 65_536, 262_144, 1_048_576, 4_194_304];

fn fl_calloc_cycle(size: usize) -> u64 {
    // SAFETY: the benchmark checks the allocation before reading its first byte
    // and returns the pointer to the same FrankenLibC allocator.
    unsafe {
        let ptr = frankenlibc_abi::malloc_abi::calloc(1, size);
        assert!(!ptr.is_null(), "FrankenLibC calloc failed in paired bench");
        let first = ptr.cast::<u8>().read_volatile();
        frankenlibc_abi::malloc_abi::free(ptr);
        (ptr as usize as u64).rotate_left(17) ^ u64::from(first)
    }
}

fn host_calloc_cycle(size: usize, host: &HostAllocator) -> u64 {
    // SAFETY: the benchmark checks the allocation before reading its first byte
    // and returns the pointer to the same isolated host allocator.
    unsafe {
        let ptr = (host.calloc)(1, size);
        assert!(!ptr.is_null(), "host glibc calloc failed in paired bench");
        let first = ptr.cast::<u8>().read_volatile();
        (host.free)(ptr);
        (ptr as usize as u64).rotate_left(17) ^ u64::from(first)
    }
}

fn calibrate_paired_iters(arm_a: &mut impl FnMut() -> u64, arm_b: &mut impl FnMut() -> u64) -> u64 {
    let mut iters = 1u64;
    loop {
        let (a_ns_per_op, _) = time_arm(iters, arm_a);
        let (b_ns_per_op, _) = time_arm(iters, arm_b);
        let faster_total_ns = a_ns_per_op.min(b_ns_per_op) * iters as f64;
        if faster_total_ns >= MIN_ARM_SAMPLE_NS as f64 || iters >= MAX_PAIRED_ITERS {
            return iters;
        }
        iters = iters.saturating_mul(2).min(MAX_PAIRED_ITERS);
    }
}

fn run_bench_contract() {
    let host = host_allocator();
    for &size in SIZES {
        let mut calibrate_a = || fl_calloc_cycle(size);
        let mut calibrate_b = || host_calloc_cycle(size, host);
        let iters = calibrate_paired_iters(&mut calibrate_a, &mut calibrate_b);

        let null = paired(
            PAIRED_ROUNDS,
            iters,
            || fl_calloc_cycle(size),
            || fl_calloc_cycle(size),
        );
        let real = paired(
            PAIRED_ROUNDS,
            iters,
            || fl_calloc_cycle(size),
            || host_calloc_cycle(size, host),
        );
        report_pair("null", size, iters, &null);
        report_pair("real", size, iters, &real);
        println!(
            "CALLOC_BENCH_GATE size={size} ratio_fl_over_glibc={:.6} decidable_2x_margin={}",
            real.ratio_p50,
            claim_clears_null_with_2x_margin(&null, real.ratio_p50),
        );
    }
}

fn bench_calloc(c: &mut Criterion) {
    let host = host_allocator();
    let mut group = c.benchmark_group("calloc_cycle");
    // Large sizes are slow; cap measurement so the run stays bounded.
    group.sample_size(30);

    for &size in SIZES {
        // FrankenLibC calloc -- NEW lever path (alloc_zeroed, no explicit memset).
        let fl_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("fl", size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let p = unsafe { frankenlibc_abi::malloc_abi::calloc(1, sz) };
                    black_box(p);
                    unsafe { frankenlibc_abi::malloc_abi::free(p) };
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                fl_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        fl_stats.borrow().report("fl", size);

        // FrankenLibC OLD calloc cost model: malloc + explicit `write_bytes(0, n)`.
        // This reproduces the pre-lever path (`pipeline.allocate` then a full
        // zero pass) using the same fl allocator/membrane, so the only variable
        // vs the `fl` arm above is the redundant memset the lever removes. This
        // is the controlled baseline-vs-candidate measurement, same process and
        // same worker.
        let fl_old_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("fl_old", size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let p = unsafe { frankenlibc_abi::malloc_abi::malloc(sz) };
                    if !p.is_null() {
                        // SAFETY: malloc returned `sz` valid bytes.
                        unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0, sz) };
                    }
                    black_box(p);
                    unsafe { frankenlibc_abi::malloc_abi::free(p) };
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                fl_old_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        fl_old_stats.borrow().report("fl_old", size);

        // FrankenLibC NATIVE host path (bd-f874go diagnostic): the bare
        // main-namespace glibc `calloc`/`free` that the deployed strict path
        // delegates to, with NO membrane bookkeeping. Isolates the membrane's
        // own per-call cost (= fl vs fl_native) from the cost of the host
        // allocator running on the busy main-namespace heap (= fl_native vs
        // glibc, where `glibc` uses a pristine dlmopen-isolated heap).
        let fl_native_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("fl_native", size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let p = unsafe {
                        frankenlibc_abi::malloc_abi::native_calloc_probe_for_bench(1, sz)
                    };
                    black_box(p);
                    unsafe { frankenlibc_abi::malloc_abi::native_free_probe_for_bench(p) };
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                fl_native_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        fl_native_stats.borrow().report("fl_native", size);

        // Host glibc calloc (isolated namespace).
        let glibc_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("glibc", size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let p = unsafe { (host.calloc)(1, sz) };
                    black_box(p);
                    unsafe { (host.free)(p) };
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                glibc_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        glibc_stats.borrow().report("glibc", size);
    }

    group.finish();
}

const REALLOC_CASES: &[(&str, usize, usize)] = &[
    ("same_256", 256, 256),
    ("same_class_shrink_256_to_240", 256, 240),
    ("cross_class_shrink_256_to_128", 256, 128),
    ("same_class_shrink_4096_to_3584", 4096, 3584),
];

fn bench_realloc(c: &mut Criterion) {
    let host = host_allocator();
    let mut group = c.benchmark_group("realloc_cycle");
    group.sample_size(30);

    for &(label, initial_size, target_size) in REALLOC_CASES {
        let ops_per_iter = if initial_size == target_size { 1 } else { 2 };

        let fl_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("fl", label), &label, |b, _| {
            b.iter_custom(|iters| {
                let mut p = unsafe { frankenlibc_abi::malloc_abi::malloc(initial_size) };
                assert!(!p.is_null(), "frankenlibc malloc failed in realloc bench");
                let start = Instant::now();
                for _ in 0..iters {
                    let out = unsafe { frankenlibc_abi::malloc_abi::realloc(p, target_size) };
                    assert!(!out.is_null(), "frankenlibc realloc failed in bench");
                    p = black_box(out);
                    if target_size != initial_size {
                        let back = unsafe { frankenlibc_abi::malloc_abi::realloc(p, initial_size) };
                        assert!(
                            !back.is_null(),
                            "frankenlibc realloc restore failed in bench"
                        );
                        p = black_box(back);
                    }
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                unsafe { frankenlibc_abi::malloc_abi::free(p) };
                fl_stats
                    .borrow_mut()
                    .record(iters.saturating_mul(ops_per_iter), dur);
                dur
            });
        });
        fl_stats.borrow().report_workload("fl", label);

        let glibc_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("glibc", label), &label, |b, _| {
            b.iter_custom(|iters| {
                let mut p = unsafe { (host.calloc)(1, initial_size) };
                assert!(!p.is_null(), "host glibc calloc failed in realloc bench");
                let start = Instant::now();
                for _ in 0..iters {
                    let out = unsafe { (host.realloc)(p, target_size) };
                    assert!(!out.is_null(), "host glibc realloc failed in bench");
                    p = black_box(out);
                    if target_size != initial_size {
                        let back = unsafe { (host.realloc)(p, initial_size) };
                        assert!(
                            !back.is_null(),
                            "host glibc realloc restore failed in bench"
                        );
                        p = black_box(back);
                    }
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                unsafe { (host.free)(p) };
                glibc_stats
                    .borrow_mut()
                    .record(iters.saturating_mul(ops_per_iter), dur);
                dur
            });
        });
        glibc_stats.borrow().report_workload("glibc", label);
    }

    group.finish();
}

criterion_group!(benches, bench_calloc, bench_realloc);

fn main() {
    println!("bench_elf_sha256={}", self_identity());
    run_bench_contract();
    benches();
}
