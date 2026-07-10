//! Allocator benchmarks.
//!
//! Includes a contention benchmark matrix for bd-byd9.2:
//! flat-combining vs lock-based baselines under varying thread counts,
//! operation mixes, and batch sizes.

use std::fs::{self, File, create_dir_all};
use std::hint::black_box;
use std::io::Write;
#[cfg(feature = "abi-bench")]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use frankenlibc_core::malloc::size_class::{SizeClassIndex, small_bin_index};

const FLAT_SLOTS: usize = 128;
const FC_OP_NONE: usize = 0;
const FC_OP_READ: usize = 1;
const FC_OP_ALLOC: usize = 2;
const FC_OP_FREE: usize = 3;
const SAMPLE_STRIDE: u64 = 64;

#[cfg(feature = "abi-bench")]
const SEGMENT_SHIFT_FOR_BENCH: usize = 22;

#[cfg(feature = "abi-bench")]
struct SegmentMembershipForBench {
    base_segment: usize,
    words: Vec<u64>,
}

#[cfg(feature = "abi-bench")]
impl SegmentMembershipForBench {
    fn new(addrs: &[usize]) -> Self {
        let min_segment = addrs
            .iter()
            .map(|addr| addr >> SEGMENT_SHIFT_FOR_BENCH)
            .min()
            .expect("segment benchmark needs at least one address");
        let max_segment = addrs
            .iter()
            .map(|addr| addr >> SEGMENT_SHIFT_FOR_BENCH)
            .max()
            .expect("segment benchmark needs at least one address");
        let segment_span = max_segment - min_segment + 1;
        let mut words = vec![0u64; segment_span.div_ceil(64)];
        for &addr in addrs {
            let rel = (addr >> SEGMENT_SHIFT_FOR_BENCH) - min_segment;
            words[rel >> 6] |= 1u64 << (rel & 63);
        }
        Self {
            base_segment: min_segment,
            words,
        }
    }

    #[inline(always)]
    fn contains(&self, addr: usize) -> bool {
        let rel = (addr >> SEGMENT_SHIFT_FOR_BENCH).wrapping_sub(self.base_segment);
        let word = rel >> 6;
        let Some(bits) = self.words.get(word) else {
            return false;
        };
        (bits & (1u64 << (rel & 63))) != 0
    }
}

/// Keep the tested shift + safe bitmap indexing in one named frame while
/// amortizing the call boundary over a full batch. Inputs and the accumulated
/// result cross optimizer barriers so a pure membership call cannot be DCE'd.
#[cfg(feature = "abi-bench")]
#[inline(never)]
fn segment_bitmap_profile_batch(
    membership: &SegmentMembershipForBench,
    addrs: &[usize],
    repetitions: u64,
) -> usize {
    let mut hits = 0usize;
    for _ in 0..black_box(repetitions) {
        for &addr in black_box(addrs) {
            hits = hits.wrapping_add(membership.contains(black_box(addr)) as usize);
        }
    }
    black_box(hits)
}

#[cfg(feature = "abi-bench")]
#[inline(never)]
fn fallback_table_profile_batch(addrs: &[usize], sizes: &[usize], repetitions: u64) -> usize {
    use frankenlibc_abi::malloc_abi as malloc;

    let mut observed = 0usize;
    for _ in 0..black_box(repetitions) {
        for (index, &addr) in black_box(addrs).iter().enumerate() {
            let ptr = black_box(addr) as *mut libc::c_void;
            let size = black_box(sizes[index % sizes.len()]);
            malloc::fallback_insert_sized_for_bench(ptr, size);
            observed = observed
                .wrapping_add(black_box(malloc::fallback_size_for_bench(ptr)).unwrap_or_default());
            observed = observed.wrapping_add(
                black_box(malloc::fallback_remove_sized_for_bench(ptr)).unwrap_or_default(),
            );
        }
    }
    black_box(observed)
}

#[cfg(feature = "abi-bench")]
fn paired_cv_pct(samples: &[f64]) -> f64 {
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| {
            let delta = sample - mean;
            delta * delta
        })
        .sum::<f64>()
        / (samples.len() - 1) as f64;
    100.0 * variance.sqrt() / mean
}

#[cfg(feature = "abi-bench")]
fn segment_bench_artifact_dir() -> PathBuf {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .expect("RCH must provide CARGO_TARGET_DIR for retrievable bench artifacts");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must follow the Unix epoch")
        .as_nanos();
    let output_dir = PathBuf::from(target_dir)
        .join("criterion")
        .join("bd-dcrhgl-segment-membership")
        .join(format!("run-{}-{timestamp}", std::process::id()));
    create_dir_all(&output_dir).expect("create segment benchmark artifact directory");
    output_dir
}

#[cfg(feature = "abi-bench")]
fn profile_segment_bitmap_execution(
    output_dir: &Path,
    membership: &SegmentMembershipForBench,
    addrs: &[usize],
) -> (f64, String) {
    let perf_path = output_dir.join("candidate.perf");
    let report_path = output_dir.join("perf-report.txt");
    let pid = std::process::id().to_string();
    let mut perf = Command::new("perf")
        .args(["record", "-F", "4999", "--call-graph", "fp", "-p"])
        .arg(&pid)
        .arg("-o")
        .arg(&perf_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn remote perf record for segment membership");
    thread::sleep(Duration::from_millis(250));
    assert!(
        perf.try_wait().expect("poll remote perf record").is_none(),
        "perf record exited before the candidate workload"
    );

    let profile_start = Instant::now();
    let mut checksum = 0usize;
    while profile_start.elapsed() < Duration::from_secs(2) {
        checksum ^=
            segment_bitmap_profile_batch(black_box(membership), black_box(addrs), black_box(4_000));
    }
    black_box(checksum);

    let signal_status = Command::new("kill")
        .arg("-INT")
        .arg(perf.id().to_string())
        .status()
        .expect("signal remote perf record");
    assert!(
        signal_status.success(),
        "failed to stop perf record cleanly"
    );
    let perf_status = perf.wait().expect("wait for remote perf record");
    assert!(
        perf_status.success() || perf_status.signal() == Some(libc::SIGINT),
        "remote perf record failed: {perf_status}"
    );
    let perf_bytes = fs::metadata(&perf_path)
        .expect("stat candidate perf artifact")
        .len();
    assert!(perf_bytes > 0, "candidate perf artifact is empty");

    let report = Command::new("perf")
        .args([
            "report",
            "--stdio",
            "--no-children",
            "--percent-limit",
            "0.01",
            "--sort=symbol",
            "--call-graph",
            "none",
            "-i",
        ])
        .arg(&perf_path)
        .output()
        .expect("render remote segment membership perf report");
    assert!(report.status.success(), "remote perf report failed");
    fs::write(&report_path, &report.stdout).expect("write retrievable perf report");
    assert!(
        fs::metadata(&report_path)
            .expect("stat candidate perf report")
            .len()
            > 0,
        "candidate perf report is empty"
    );

    let report_text = String::from_utf8(report.stdout).expect("perf report must be UTF-8");
    let candidate_line = report_text
        .lines()
        .find(|line| line.contains("segment_bitmap_profile_batch"))
        .expect("candidate frame missing from perf report")
        .trim()
        .to_owned();
    let self_pct = candidate_line
        .split_whitespace()
        .next()
        .and_then(|field| field.strip_suffix('%'))
        .and_then(|field| field.parse::<f64>().ok())
        .expect("parse candidate self-time percentage");
    assert!(self_pct > 0.0, "candidate self-time must be non-zero");
    println!(
        "MALLOC_SEGMENT_BITMAP_SELF_TIME self_pct={self_pct:.2} perf_bytes={perf_bytes} frame={candidate_line}"
    );
    (self_pct, candidate_line)
}

#[derive(Default)]
struct BaselineBenchStats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl BaselineBenchStats {
    fn record(&mut self, iters: u64, dur: Duration) {
        if iters == 0 {
            return;
        }
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, mode_label: &str, bench_label: &str) {
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
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };

        println!(
            "MALLOC_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
            mode_label,
            bench_label,
            samples.len(),
            p50,
            p95,
            p99,
            mean,
            throughput_ops_s
        );
    }
}

fn mode_label() -> &'static str {
    match std::env::var("FRANKENLIBC_MODE").ok().as_deref() {
        Some("hardened") => "hardened",
        Some("strict") => "strict",
        _ => "raw",
    }
}

#[derive(Clone, Copy, Default)]
struct AllocStats {
    total_allocated: u64,
    total_freed: u64,
    active_allocations: u64,
    live_bytes: u64,
    peak_usage: u64,
}

impl AllocStats {
    fn apply_alloc(&mut self, size: usize) {
        let s = size as u64;
        self.total_allocated = self.total_allocated.saturating_add(s);
        self.active_allocations = self.active_allocations.saturating_add(1);
        self.live_bytes = self.live_bytes.saturating_add(s);
        self.peak_usage = self.peak_usage.max(self.live_bytes);
    }

    fn apply_free(&mut self, size: usize) {
        let s = size as u64;
        self.total_freed = self.total_freed.saturating_add(s);
        self.active_allocations = self.active_allocations.saturating_sub(1);
        self.live_bytes = self.live_bytes.saturating_sub(s);
    }
}

#[repr(align(128))]
struct FlatSlot {
    op: AtomicUsize,
    size: AtomicUsize,
    request_id: AtomicU64,
    completed_id: AtomicU64,
    result_live_bytes: AtomicU64,
}

impl FlatSlot {
    const fn new() -> Self {
        Self {
            op: AtomicUsize::new(FC_OP_NONE),
            size: AtomicUsize::new(0),
            request_id: AtomicU64::new(0),
            completed_id: AtomicU64::new(0),
            result_live_bytes: AtomicU64::new(0),
        }
    }
}

struct FlatCombiningBackend {
    combiner_lock: AtomicBool,
    next_slot: AtomicUsize,
    slots: [FlatSlot; FLAT_SLOTS],
    state: Mutex<AllocStats>,
    scan_rounds: AtomicU64,
    scan_total_ns: AtomicU64,
}

impl FlatCombiningBackend {
    fn new() -> Self {
        Self {
            combiner_lock: AtomicBool::new(false),
            next_slot: AtomicUsize::new(0),
            slots: [const { FlatSlot::new() }; FLAT_SLOTS],
            state: Mutex::new(AllocStats::default()),
            scan_rounds: AtomicU64::new(0),
            scan_total_ns: AtomicU64::new(0),
        }
    }

    fn slot_index(&self) -> usize {
        FC_SLOT_INDEX.with(|slot| match slot.get() {
            Some(idx) => idx,
            None => {
                let idx = self.next_slot.fetch_add(1, Ordering::Relaxed) % FLAT_SLOTS;
                slot.set(Some(idx));
                idx
            }
        })
    }

    fn apply_op(&self, op: usize, size: usize) -> u64 {
        let idx = self.slot_index();
        let slot = &self.slots[idx];
        let request_id = slot.request_id.fetch_add(1, Ordering::AcqRel) + 1;
        slot.size.store(size, Ordering::Relaxed);
        slot.op.store(op, Ordering::Release);

        self.try_combine_round();

        let mut spins = 0_u32;
        while slot.completed_id.load(Ordering::Acquire) < request_id {
            self.try_combine_round();
            if spins < 256 {
                spins += 1;
                std::hint::spin_loop();
            } else {
                spins = 0;
                thread::yield_now();
            }
        }
        slot.result_live_bytes.load(Ordering::Acquire)
    }

    fn try_combine_round(&self) {
        if self
            .combiner_lock
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let start = Instant::now();
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        for slot in &self.slots {
            let op = slot.op.swap(FC_OP_NONE, Ordering::AcqRel);
            if op == FC_OP_NONE {
                continue;
            }

            let size = slot.size.load(Ordering::Relaxed);
            match op {
                FC_OP_ALLOC => state.apply_alloc(size),
                FC_OP_FREE => state.apply_free(size),
                FC_OP_READ => {}
                _ => {}
            }

            slot.result_live_bytes
                .store(state.live_bytes, Ordering::Release);
            let req = slot.request_id.load(Ordering::Acquire);
            slot.completed_id.store(req, Ordering::Release);
        }

        let elapsed_ns = start.elapsed().as_nanos() as u64;
        self.scan_rounds.fetch_add(1, Ordering::Relaxed);
        self.scan_total_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
        self.combiner_lock.store(false, Ordering::Release);
    }

    fn average_scan_ns(&self) -> f64 {
        let rounds = self.scan_rounds.load(Ordering::Relaxed);
        if rounds == 0 {
            0.0
        } else {
            self.scan_total_ns.load(Ordering::Relaxed) as f64 / rounds as f64
        }
    }
}

struct MutexBackend(Mutex<AllocStats>);

impl MutexBackend {
    fn new() -> Self {
        Self(Mutex::new(AllocStats::default()))
    }
}

struct RwLockBackend(RwLock<AllocStats>);

impl RwLockBackend {
    fn new() -> Self {
        Self(RwLock::new(AllocStats::default()))
    }
}

struct AtomicBackend {
    total_allocated: AtomicU64,
    total_freed: AtomicU64,
    active_allocations: AtomicU64,
    live_bytes: AtomicU64,
    peak_usage: AtomicU64,
}

impl AtomicBackend {
    fn new() -> Self {
        Self {
            total_allocated: AtomicU64::new(0),
            total_freed: AtomicU64::new(0),
            active_allocations: AtomicU64::new(0),
            live_bytes: AtomicU64::new(0),
            peak_usage: AtomicU64::new(0),
        }
    }

    fn current_live_bytes(&self) -> u64 {
        self.live_bytes.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy)]
enum BackendKind {
    FlatCombining,
    Mutex,
    RwLock,
    Atomic,
}

impl BackendKind {
    const ALL: [Self; 4] = [Self::FlatCombining, Self::Mutex, Self::RwLock, Self::Atomic];

    const fn as_str(self) -> &'static str {
        match self {
            Self::FlatCombining => "flat_combining",
            Self::Mutex => "mutex",
            Self::RwLock => "rwlock",
            Self::Atomic => "atomic",
        }
    }
}

#[derive(Clone, Copy)]
enum OpMix {
    ReadOnly,
    WriteOnly,
    Mixed80_20,
}

impl OpMix {
    const ALL: [Self; 3] = [Self::ReadOnly, Self::WriteOnly, Self::Mixed80_20];

    const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WriteOnly => "write_only",
            Self::Mixed80_20 => "mixed_80_20",
        }
    }
}

#[derive(Clone, Copy)]
enum BenchOp {
    Read,
    Alloc,
    Free,
}

struct ThreadResult {
    op_count: u64,
    elapsed_ns: u128,
    samples_ns_per_op: Vec<f64>,
}

struct BenchRecord {
    implementation: BackendKind,
    op_mix: OpMix,
    batch_size: usize,
    thread_count: usize,
    throughput_ops_s: f64,
    p50_ns_op: f64,
    p95_ns_op: f64,
    p99_ns_op: f64,
    fairness_cov_pct: f64,
    combiner_scan_ns_avg: f64,
    llc_misses: u64,
}

thread_local! {
    static FC_SLOT_INDEX: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn bench_alloc_free_cycle(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096, 32768];
    let mode = mode_label();
    let stats = std::cell::RefCell::new(BaselineBenchStats::default());
    let mut group = c.benchmark_group("alloc_free_cycle");

    for &size in sizes {
        group.bench_with_input(BenchmarkId::new("system", size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let v = vec![0u8; sz];
                    black_box(v);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
    }
    group.finish();
    stats.borrow().report(mode, "alloc_free_cycle");
}

fn bench_alloc_burst(c: &mut Criterion) {
    let mode = mode_label();
    let stats = std::cell::RefCell::new(BaselineBenchStats::default());
    let mut group = c.benchmark_group("alloc_burst");

    group.bench_function("1000x64B", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let allocs: Vec<Vec<u8>> = (0..1000).map(|_| vec![0u8; 64]).collect();
                black_box(allocs);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });

    group.finish();
    stats.borrow().report(mode, "alloc_burst");
}

fn bench_bounded_index_overhead(c: &mut Criterion) {
    let buckets = [0usize; 32];
    let index = 11usize;
    let mut group = c.benchmark_group("bounded_index");

    group.bench_function("raw_usize", |b| {
        b.iter(|| black_box(buckets[black_box(index)]))
    });

    group.bench_function("bounded_try_from", |b| {
        b.iter(|| {
            let bounded = SizeClassIndex::try_from(black_box(index))
                .expect("benchmark index should remain in range");
            black_box(buckets[bounded.get()])
        })
    });

    group.finish();
}

// Size-class lookup: the malloc hot path maps a request size to a bin on every
// allocation. Compares the shipped O(1) granule LUT (small_bin_index) against an
// inline copy of the original O(32) linear scan, in the SAME bench run so the
// A/B shares one worker (cross-invocation rch speeds vary ~2x).
fn bench_size_class_lookup(c: &mut Criterion) {
    // Mirror of the in-crate SIZE_TABLE (private), for the linear baseline.
    const SIZE_TABLE: [usize; 32] = [
        16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 288, 320, 352, 384, 448, 512, 640,
        768, 896, 1024, 1280, 1536, 2048, 2560, 3072, 4096, 8192, 16384, 24576, 32768,
    ];
    fn linear(size: usize) -> usize {
        let size = size.max(16);
        if size > 32768 {
            return 32;
        }
        for (i, &cs) in SIZE_TABLE.iter().enumerate() {
            if size <= cs {
                return i;
            }
        }
        32
    }
    // A spread of request sizes biased toward the larger classes (where the
    // linear scan does the most comparisons) but covering the whole range.
    let sizes: [usize; 16] = [
        8, 24, 100, 200, 300, 500, 900, 1500, 2000, 3000, 5000, 9000, 17000, 25000, 30000, 32768,
    ];

    let mut group = c.benchmark_group("size_class_lookup");
    group.bench_function("lut", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for &s in &sizes {
                acc += small_bin_index(black_box(s)).map_or(32, |i| i.get());
            }
            black_box(acc)
        })
    });
    group.bench_function("linear_scan", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for &s in &sizes {
                acc += linear(black_box(s));
            }
            black_box(acc)
        })
    });
    group.finish();
}

#[cfg(feature = "abi-bench")]
fn bench_segment_bitmap_paired(c: &mut Criterion) {
    const ADDRESS_COUNT: usize = 256;
    const WARMUP_PAIRS: usize = 4;
    const PAIRED_ROUNDS: usize = 31;
    const REPETITIONS_PER_ROUND: u64 = 4_000;

    let output_dir = segment_bench_artifact_dir();
    let sizes = [16usize, 24, 64, 256];
    let mut blocks: Vec<Vec<u8>> = (0..ADDRESS_COUNT)
        .map(|index| vec![0u8; sizes[index % sizes.len()]])
        .collect();
    let addrs: Vec<usize> = blocks
        .iter_mut()
        .map(|block| black_box(block.as_mut_ptr() as usize))
        .collect();
    let membership = SegmentMembershipForBench::new(black_box(&addrs));

    let expected_hits = ADDRESS_COUNT * REPETITIONS_PER_ROUND as usize;
    assert_eq!(
        segment_bitmap_profile_batch(&membership, &addrs, REPETITIONS_PER_ROUND),
        expected_hits
    );
    assert!(!membership.contains(black_box(0)));
    assert!(!membership.contains(black_box(usize::MAX)));
    let expected_table_observation = addrs
        .iter()
        .enumerate()
        .map(|(index, _)| 2 * sizes[index % sizes.len()])
        .sum::<usize>();
    assert_eq!(
        fallback_table_profile_batch(&addrs, &sizes, 1),
        expected_table_observation
    );
    let (candidate_self_pct, _) =
        profile_segment_bitmap_execution(&output_dir, &membership, &addrs);

    for warmup in 0..WARMUP_PAIRS {
        if warmup.is_multiple_of(2) {
            black_box(fallback_table_profile_batch(&addrs, &sizes, 100));
            black_box(segment_bitmap_profile_batch(&membership, &addrs, 100));
        } else {
            black_box(segment_bitmap_profile_batch(&membership, &addrs, 100));
            black_box(fallback_table_profile_batch(&addrs, &sizes, 100));
        }
    }

    let operations = REPETITIONS_PER_ROUND as f64 * ADDRESS_COUNT as f64;
    let mut table_samples = Vec::with_capacity(PAIRED_ROUNDS);
    let mut segment_samples = Vec::with_capacity(PAIRED_ROUNDS);
    let mut paired_ratios = Vec::with_capacity(PAIRED_ROUNDS);

    for round in 0..PAIRED_ROUNDS {
        let measure_table = || {
            let start = Instant::now();
            black_box(fallback_table_profile_batch(
                black_box(&addrs),
                black_box(&sizes),
                black_box(REPETITIONS_PER_ROUND),
            ));
            start.elapsed().as_nanos() as f64 / operations
        };
        let measure_segment = || {
            let start = Instant::now();
            black_box(segment_bitmap_profile_batch(
                black_box(&membership),
                black_box(&addrs),
                black_box(REPETITIONS_PER_ROUND),
            ));
            start.elapsed().as_nanos() as f64 / operations
        };

        let (table_ns, segment_ns) = if round.is_multiple_of(2) {
            (measure_table(), measure_segment())
        } else {
            let segment_ns = measure_segment();
            let table_ns = measure_table();
            (table_ns, segment_ns)
        };
        table_samples.push(table_ns);
        segment_samples.push(segment_ns);
        paired_ratios.push(segment_ns / table_ns);
    }

    let mut sorted_table = table_samples.clone();
    let mut sorted_segment = segment_samples.clone();
    let mut sorted_ratios = paired_ratios.clone();
    sorted_table.sort_by(f64::total_cmp);
    sorted_segment.sort_by(f64::total_cmp);
    sorted_ratios.sort_by(f64::total_cmp);
    let table_p50 = percentile_sorted(&sorted_table, 0.50);
    let segment_p50 = percentile_sorted(&sorted_segment, 0.50);
    let ratio_p50 = percentile_sorted(&sorted_ratios, 0.50);
    let table_cv = paired_cv_pct(&table_samples);
    let segment_cv = paired_cv_pct(&segment_samples);
    let paired_ratio_cv = paired_cv_pct(&paired_ratios);

    let paired_json = format!(
        concat!(
            "{{\n",
            "  \"samples\": {samples},\n",
            "  \"warmup_pairs\": {warmup_pairs},\n",
            "  \"ops_per_arm_sample\": {ops_per_arm_sample},\n",
            "  \"table_p50_ns\": {table_p50:.6},\n",
            "  \"segment_p50_ns\": {segment_p50:.6},\n",
            "  \"segment_over_table_p50\": {ratio_p50:.8},\n",
            "  \"table_cv_pct\": {table_cv:.6},\n",
            "  \"segment_cv_pct\": {segment_cv:.6},\n",
            "  \"paired_ratio_cv_pct\": {paired_ratio_cv:.6},\n",
            "  \"candidate_self_pct\": {candidate_self_pct:.6},\n",
            "  \"table_samples_ns\": {:?},\n",
            "  \"segment_samples_ns\": {:?},\n",
            "  \"paired_ratios\": {:?}\n",
            "}}\n"
        ),
        table_samples,
        segment_samples,
        paired_ratios,
        samples = PAIRED_ROUNDS,
        warmup_pairs = WARMUP_PAIRS,
        ops_per_arm_sample = REPETITIONS_PER_ROUND * ADDRESS_COUNT as u64,
        table_p50 = table_p50,
        segment_p50 = segment_p50,
        ratio_p50 = ratio_p50,
        table_cv = table_cv,
        segment_cv = segment_cv,
        paired_ratio_cv = paired_ratio_cv,
        candidate_self_pct = candidate_self_pct,
    );
    let paired_path = output_dir.join("paired.json");
    fs::write(&paired_path, paired_json).expect("write retrievable paired benchmark artifact");
    let paired_bytes = fs::metadata(&paired_path)
        .expect("stat paired benchmark artifact")
        .len();
    assert!(paired_bytes > 0, "paired benchmark artifact is empty");

    println!(
        "MALLOC_SEGMENT_BITMAP_PAIRED samples={PAIRED_ROUNDS} ops_per_arm_sample={} table_p50_ns={table_p50:.3} segment_p50_ns={segment_p50:.3} segment_over_table_p50={ratio_p50:.4} saved_ns={:.3} table_cv_pct={:.2} segment_cv_pct={:.2} paired_ratio_cv_pct={:.2}",
        REPETITIONS_PER_ROUND * ADDRESS_COUNT as u64,
        table_p50 - segment_p50,
        table_cv,
        segment_cv,
        paired_ratio_cv,
    );
    println!(
        "MALLOC_SEGMENT_BITMAP_ARTIFACTS output_dir={} paired_bytes={paired_bytes}",
        output_dir.display()
    );

    // This single candidate-only Criterion member exists for `perf` execution
    // integrity. The keep/reject score comes from the alternating paired sampler
    // above, never from sequential Criterion group members.
    let mut group = c.benchmark_group("segment_bitmap_integrity");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("profile_candidate", |b| {
        b.iter(|| {
            black_box(segment_bitmap_profile_batch(
                black_box(&membership),
                black_box(&addrs),
                black_box(64),
            ))
        })
    });
    group.finish();
}

#[cfg(not(feature = "abi-bench"))]
fn bench_segment_bitmap_paired(_c: &mut Criterion) {}

fn choose_op(mix: OpMix, op_index: u64, toggle: &mut bool) -> BenchOp {
    match mix {
        OpMix::ReadOnly => BenchOp::Read,
        OpMix::WriteOnly => {
            let op = if *toggle {
                BenchOp::Alloc
            } else {
                BenchOp::Free
            };
            *toggle = !*toggle;
            op
        }
        OpMix::Mixed80_20 => {
            if op_index.is_multiple_of(5) {
                BenchOp::Read
            } else {
                let op = if *toggle {
                    BenchOp::Alloc
                } else {
                    BenchOp::Free
                };
                *toggle = !*toggle;
                op
            }
        }
    }
}

fn run_flat_op(backend: &FlatCombiningBackend, op: BenchOp, size: usize) {
    match op {
        BenchOp::Read => {
            let _ = backend.apply_op(FC_OP_READ, 0);
        }
        BenchOp::Alloc => {
            let _ = backend.apply_op(FC_OP_ALLOC, size);
        }
        BenchOp::Free => {
            let _ = backend.apply_op(FC_OP_FREE, size);
        }
    }
}

fn run_mutex_op(backend: &MutexBackend, op: BenchOp, size: usize) {
    let mut guard = match backend.0.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match op {
        BenchOp::Read => {
            let _ = guard.live_bytes;
        }
        BenchOp::Alloc => guard.apply_alloc(size),
        BenchOp::Free => guard.apply_free(size),
    }
}

fn run_rwlock_op(backend: &RwLockBackend, op: BenchOp, size: usize) {
    match op {
        BenchOp::Read => {
            let guard = match backend.0.read() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let _ = guard.live_bytes;
        }
        BenchOp::Alloc => {
            let mut guard = match backend.0.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.apply_alloc(size);
        }
        BenchOp::Free => {
            let mut guard = match backend.0.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.apply_free(size);
        }
    }
}

fn run_atomic_op(backend: &AtomicBackend, op: BenchOp, size: usize) {
    let s = size as u64;
    match op {
        BenchOp::Read => {
            let _ = backend.current_live_bytes();
        }
        BenchOp::Alloc => {
            backend.total_allocated.fetch_add(s, Ordering::Relaxed);
            backend.active_allocations.fetch_add(1, Ordering::Relaxed);
            let new_live = backend.live_bytes.fetch_add(s, Ordering::Relaxed) + s;
            let mut peak = backend.peak_usage.load(Ordering::Relaxed);
            while new_live > peak {
                match backend.peak_usage.compare_exchange_weak(
                    peak,
                    new_live,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(cur) => peak = cur,
                }
            }
        }
        BenchOp::Free => {
            backend.total_freed.fetch_add(s, Ordering::Relaxed);
            backend.active_allocations.fetch_sub(1, Ordering::Relaxed);
            backend.live_bytes.fetch_sub(s, Ordering::Relaxed);
        }
    }
}

fn run_config(
    implementation: BackendKind,
    op_mix: OpMix,
    batch_size: usize,
    thread_count: usize,
    warmup: Duration,
    measure: Duration,
) -> BenchRecord {
    let running = Arc::new(AtomicBool::new(true));
    let barrier = Arc::new(Barrier::new(thread_count + 1));

    let flat_backend = Arc::new(FlatCombiningBackend::new());
    let mutex_backend = Arc::new(MutexBackend::new());
    let rwlock_backend = Arc::new(RwLockBackend::new());
    let atomic_backend = Arc::new(AtomicBackend::new());

    let mut handles = Vec::with_capacity(thread_count);
    for tid in 0..thread_count {
        let running = Arc::clone(&running);
        let barrier = Arc::clone(&barrier);
        let flat = Arc::clone(&flat_backend);
        let mutex = Arc::clone(&mutex_backend);
        let rwlock = Arc::clone(&rwlock_backend);
        let atomic = Arc::clone(&atomic_backend);

        handles.push(thread::spawn(move || -> ThreadResult {
            let mut op_count = 0_u64;
            let mut sample_count = 0_u64;
            let mut samples = Vec::new();
            let mut write_toggle = true;
            let mut op_index = 0_u64;
            barrier.wait();
            let run_start = Instant::now();

            while running.load(Ordering::Acquire) {
                let batch_start = Instant::now();
                for _ in 0..batch_size {
                    let size = ((tid as u64 * 131 + op_index * 17) % 2048 + 1) as usize;
                    let op = choose_op(op_mix, op_index, &mut write_toggle);
                    match implementation {
                        BackendKind::FlatCombining => run_flat_op(&flat, op, size),
                        BackendKind::Mutex => run_mutex_op(&mutex, op, size),
                        BackendKind::RwLock => run_rwlock_op(&rwlock, op, size),
                        BackendKind::Atomic => run_atomic_op(&atomic, op, size),
                    }
                    op_count = op_count.saturating_add(1);
                    op_index = op_index.saturating_add(1);
                }
                let batch_ns = batch_start.elapsed().as_nanos().max(1) as f64;
                if sample_count.is_multiple_of(SAMPLE_STRIDE) {
                    samples.push(batch_ns / batch_size as f64);
                }
                sample_count = sample_count.saturating_add(1);
            }

            ThreadResult {
                op_count,
                elapsed_ns: run_start.elapsed().as_nanos(),
                samples_ns_per_op: samples,
            }
        }));
    }

    barrier.wait();
    if warmup > Duration::ZERO {
        thread::sleep(warmup);
    }
    running.store(true, Ordering::Release);
    thread::sleep(measure);
    running.store(false, Ordering::Release);

    let mut thread_results = Vec::with_capacity(thread_count);
    for handle in handles {
        if let Ok(result) = handle.join() {
            thread_results.push(result);
        }
    }

    let total_ops = thread_results.iter().map(|r| r.op_count).sum::<u64>();
    let max_elapsed_ns = thread_results
        .iter()
        .map(|r| r.elapsed_ns)
        .max()
        .unwrap_or(measure.as_nanos().max(1));
    let elapsed_secs = (max_elapsed_ns as f64 / 1e9).max(1e-9);
    let throughput_ops_s = total_ops as f64 / elapsed_secs;

    let mut lat_samples = Vec::new();
    for result in &thread_results {
        lat_samples.extend(result.samples_ns_per_op.iter().copied());
    }
    lat_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = percentile_sorted(&lat_samples, 0.50);
    let p95 = percentile_sorted(&lat_samples, 0.95);
    let p99 = percentile_sorted(&lat_samples, 0.99);

    let per_thread_tps = thread_results
        .iter()
        .map(|r| {
            let secs = (r.elapsed_ns as f64 / 1e9).max(1e-9);
            r.op_count as f64 / secs
        })
        .collect::<Vec<_>>();
    let fairness_cov_pct = coefficient_of_variation_pct(&per_thread_tps);

    let combiner_scan_ns_avg = match implementation {
        BackendKind::FlatCombining => flat_backend.average_scan_ns(),
        _ => 0.0,
    };

    BenchRecord {
        implementation,
        op_mix,
        batch_size,
        thread_count,
        throughput_ops_s,
        p50_ns_op: p50,
        p95_ns_op: p95,
        p99_ns_op: p99,
        fairness_cov_pct,
        combiner_scan_ns_avg,
        llc_misses: 0,
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn coefficient_of_variation_pct(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean <= f64::EPSILON {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|v| {
            let d = *v - mean;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    (variance.sqrt() / mean) * 100.0
}

fn bench_output_dir() -> PathBuf {
    std::env::var("FRANKENLIBC_BENCH_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/flat_combining_stats"))
}

fn write_json(records: &[BenchRecord], out_dir: &Path) -> std::io::Result<()> {
    let mut file = File::create(out_dir.join("flat_combining_benchmark.json"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    writeln!(file, "{{")?;
    writeln!(file, "  \"generated_unix_ts\": {now},")?;
    writeln!(file, "  \"records\": [")?;
    for (idx, r) in records.iter().enumerate() {
        let comma = if idx + 1 == records.len() { "" } else { "," };
        writeln!(
            file,
            "    {{\"implementation\":\"{}\",\"op_mix\":\"{}\",\"batch_size\":{},\"thread_count\":{},\"throughput_ops_s\":{:.3},\"p50_ns_op\":{:.3},\"p95_ns_op\":{:.3},\"p99_ns_op\":{:.3},\"fairness_cov_pct\":{:.3},\"combiner_scan_ns_avg\":{:.3},\"llc_misses\":{}}}{}",
            r.implementation.as_str(),
            r.op_mix.as_str(),
            r.batch_size,
            r.thread_count,
            r.throughput_ops_s,
            r.p50_ns_op,
            r.p95_ns_op,
            r.p99_ns_op,
            r.fairness_cov_pct,
            r.combiner_scan_ns_avg,
            r.llc_misses,
            comma
        )?;
    }
    writeln!(file, "  ]")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn write_dat(records: &[BenchRecord], out_dir: &Path) -> std::io::Result<()> {
    let mut throughput = File::create(out_dir.join("throughput_vs_threads.dat"))?;
    writeln!(
        throughput,
        "# impl op_mix batch thread_count throughput_ops_s p50_ns p95_ns p99_ns fairness_cov_pct scan_ns_avg"
    )?;
    for r in records {
        writeln!(
            throughput,
            "{} {} {} {} {:.3} {:.3} {:.3} {:.3} {:.3} {:.3}",
            r.implementation.as_str(),
            r.op_mix.as_str(),
            r.batch_size,
            r.thread_count,
            r.throughput_ops_s,
            r.p50_ns_op,
            r.p95_ns_op,
            r.p99_ns_op,
            r.fairness_cov_pct,
            r.combiner_scan_ns_avg
        )?;
    }

    let mut latency = File::create(out_dir.join("latency_cdf.dat"))?;
    writeln!(
        latency,
        "# impl op_mix batch thread_count p50_ns p95_ns p99_ns"
    )?;
    for r in records {
        writeln!(
            latency,
            "{} {} {} {} {:.3} {:.3} {:.3}",
            r.implementation.as_str(),
            r.op_mix.as_str(),
            r.batch_size,
            r.thread_count,
            r.p50_ns_op,
            r.p95_ns_op,
            r.p99_ns_op
        )?;
    }

    let mut cache = File::create(out_dir.join("cache_misses.dat"))?;
    writeln!(cache, "# impl op_mix batch thread_count llc_misses")?;
    for r in records {
        writeln!(
            cache,
            "{} {} {} {} {}",
            r.implementation.as_str(),
            r.op_mix.as_str(),
            r.batch_size,
            r.thread_count,
            r.llc_misses
        )?;
    }
    Ok(())
}

fn write_gnuplot_scripts(out_dir: &Path) -> std::io::Result<()> {
    let throughput_gp = r#"set terminal svg size 1200,700
set output "throughput_vs_threads.svg"
set title "Flat Combining vs Lock Baselines (Throughput)"
set xlabel "Threads"
set ylabel "Ops/s"
set key left top
set grid
plot \
  "throughput_vs_threads.dat" using 4:5 every :::0::99999 with linespoints title "all-config points"
"#;

    let latency_gp = r#"set terminal svg size 1200,700
set output "latency_cdf.svg"
set title "Latency Summary (p50/p95/p99)"
set xlabel "Threads"
set ylabel "ns/op"
set key left top
set grid
plot \
  "latency_cdf.dat" using 4:5 with linespoints title "p50", \
  "latency_cdf.dat" using 4:6 with linespoints title "p95", \
  "latency_cdf.dat" using 4:7 with linespoints title "p99"
"#;

    let cache_gp = r#"set terminal svg size 1200,700
set output "cache_misses.svg"
set title "LLC Misses (if populated)"
set xlabel "Threads"
set ylabel "LLC Misses"
set key left top
set grid
plot "cache_misses.dat" using 4:5 with linespoints title "llc_misses"
"#;

    let mut f1 = File::create(out_dir.join("throughput_vs_threads.gp"))?;
    f1.write_all(throughput_gp.as_bytes())?;
    let mut f2 = File::create(out_dir.join("latency_cdf.gp"))?;
    f2.write_all(latency_gp.as_bytes())?;
    let mut f3 = File::create(out_dir.join("cache_misses.gp"))?;
    f3.write_all(cache_gp.as_bytes())?;
    Ok(())
}

fn run_flat_combining_matrix() -> std::io::Result<Vec<BenchRecord>> {
    let thread_counts = [1_usize, 2, 4, 8, 16, 32, 64];
    let batch_sizes = [1_usize, 10, 100, 1000];

    let warmup_ms = std::env::var("FRANKENLIBC_FLAT_BENCH_WARMUP_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(250);
    let measure_ms = std::env::var("FRANKENLIBC_FLAT_BENCH_MEASURE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(750);
    let warmup = Duration::from_millis(warmup_ms);
    let measure = Duration::from_millis(measure_ms.max(1));

    let mut records = Vec::new();
    for implementation in BackendKind::ALL {
        for op_mix in OpMix::ALL {
            for batch_size in batch_sizes {
                for thread_count in thread_counts {
                    let rec = run_config(
                        implementation,
                        op_mix,
                        batch_size,
                        thread_count,
                        warmup,
                        measure,
                    );
                    println!(
                        "FLAT_COMBINING_BENCH impl={} op_mix={} batch={} threads={} throughput_ops_s={:.3} p50_ns={:.3} p95_ns={:.3} p99_ns={:.3} fairness_cov_pct={:.3} scan_ns_avg={:.3}",
                        rec.implementation.as_str(),
                        rec.op_mix.as_str(),
                        rec.batch_size,
                        rec.thread_count,
                        rec.throughput_ops_s,
                        rec.p50_ns_op,
                        rec.p95_ns_op,
                        rec.p99_ns_op,
                        rec.fairness_cov_pct,
                        rec.combiner_scan_ns_avg
                    );
                    records.push(rec);
                }
            }
        }
    }
    Ok(records)
}

fn bench_flat_combining_vs_lock_contention(_c: &mut Criterion) {
    if std::env::var("FRANKENLIBC_ENABLE_FLAT_BENCH")
        .ok()
        .as_deref()
        != Some("1")
    {
        println!(
            "MALLOC_BENCH_INFO flat-combining matrix skipped; set FRANKENLIBC_ENABLE_FLAT_BENCH=1 to run"
        );
        return;
    }

    let out_dir = bench_output_dir();
    if let Err(err) = create_dir_all(&out_dir) {
        eprintln!(
            "MALLOC_BENCH_ERROR could not create output dir {}: {err}",
            out_dir.display()
        );
        return;
    }

    match run_flat_combining_matrix() {
        Ok(records) => {
            if let Err(err) = write_json(&records, &out_dir) {
                eprintln!("MALLOC_BENCH_ERROR failed writing JSON artifacts: {err}");
            }
            if let Err(err) = write_dat(&records, &out_dir) {
                eprintln!("MALLOC_BENCH_ERROR failed writing .dat artifacts: {err}");
            }
            if let Err(err) = write_gnuplot_scripts(&out_dir) {
                eprintln!("MALLOC_BENCH_ERROR failed writing gnuplot scripts: {err}");
            }
            println!(
                "MALLOC_BENCH_ARTIFACTS output_dir={}",
                out_dir.to_string_lossy()
            );
        }
        Err(err) => {
            eprintln!("MALLOC_BENCH_ERROR flat-combining matrix failed: {err}");
        }
    }
}

criterion_group!(
    benches,
    bench_alloc_free_cycle,
    bench_alloc_burst,
    bench_bounded_index_overhead,
    bench_size_class_lookup,
    bench_segment_bitmap_paired,
    bench_flat_combining_vs_lock_contention
);
criterion_main!(benches);
