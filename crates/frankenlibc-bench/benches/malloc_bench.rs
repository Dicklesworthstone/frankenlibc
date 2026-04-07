//! Allocator benchmarks.
//!
//! Includes a contention benchmark matrix for bd-byd9.2:
//! flat-combining vs lock-based baselines under varying thread counts,
//! operation mixes, and batch sizes.

use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use frankenlibc_core::malloc::size_class::SizeClassIndex;

const FLAT_SLOTS: usize = 128;
const FC_OP_NONE: usize = 0;
const FC_OP_READ: usize = 1;
const FC_OP_ALLOC: usize = 2;
const FC_OP_FREE: usize = 3;
const SAMPLE_STRIDE: u64 = 64;

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
    let mut group = c.benchmark_group("alloc_free_cycle");

    for &size in sizes {
        group.bench_with_input(BenchmarkId::new("system", size), &size, |b, &sz| {
            b.iter(|| {
                let v = vec![0u8; sz];
                criterion::black_box(v);
            });
        });
    }
    group.finish();
}

fn bench_alloc_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("alloc_burst");

    group.bench_function("1000x64B", |b| {
        b.iter(|| {
            let allocs: Vec<Vec<u8>> = (0..1000).map(|_| vec![0u8; 64]).collect();
            criterion::black_box(allocs);
        });
    });

    group.finish();
}

fn bench_bounded_index_overhead(c: &mut Criterion) {
    let buckets = [0usize; 32];
    let index = 11usize;
    let mut group = c.benchmark_group("bounded_index");

    group.bench_function("raw_usize", |b| {
        b.iter(|| criterion::black_box(buckets[criterion::black_box(index)]))
    });

    group.bench_function("bounded_try_from", |b| {
        b.iter(|| {
            let bounded = SizeClassIndex::try_from(criterion::black_box(index))
                .expect("benchmark index should remain in range");
            criterion::black_box(buckets[bounded.get()])
        })
    });

    group.finish();
}

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
    bench_flat_combining_vs_lock_contention
);
criterion_main!(benches);
