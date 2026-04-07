//! RCU-vs-mutex metadata read benchmark and artifact emitter for bd-3aof.3.
//!
//! The runner covers the full 7x5x3 matrix described in the bead:
//! - thread counts: 1, 2, 4, 8, 16, 32, 64
//! - read/write ratios: 100:0, 99:1, 95:5, 90:10, 50:50
//! - operations: thread metadata, size-class lookup, TLS cache lookup
//!
//! The artifact bundle is emitted under `target/metadata_read_bench/` by
//! default and can be relocated via `FRANKENLIBC_METADATA_BENCH_OUT`.

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex, TryLockError};
use std::thread;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_bench::{
    MetadataBenchRecord, MetadataImplementation, MetadataOperation, summarize_latency_samples,
    write_metadata_bench_artifacts,
};
use frankenlibc_core::malloc::size_class::{NUM_SIZE_CLASSES, bin_size};
use frankenlibc_core::rcu::{
    RcuDomain, rcu_quiescent_state, rcu_read_lock, rcu_read_unlock, rcu_register_thread,
    rcu_unregister_thread, synchronize_rcu,
};

const THREAD_COUNTS: [usize; 7] = [1, 2, 4, 8, 16, 32, 64];
const READ_RATIOS: [u8; 5] = [100, 99, 95, 90, 50];
const OPERATIONS: [MetadataOperation; 3] = [
    MetadataOperation::ThreadMetadata,
    MetadataOperation::SizeClassLookup,
    MetadataOperation::TlsCacheLookup,
];
const TLS_TAGS: usize = 64;
const DEFAULT_OPS_PER_THREAD: usize = 512;
const DEFAULT_TRIALS: usize = 3;
const DEFAULT_SAMPLE_STRIDE: usize = 8;

#[derive(Clone, PartialEq)]
struct ThreadMetadataPayload {
    tid: u64,
    generation: u64,
    flags: u64,
    stack_lo: usize,
    stack_hi: usize,
}

#[derive(Clone, PartialEq)]
struct MetadataState {
    thread: ThreadMetadataPayload,
    size_classes: [usize; NUM_SIZE_CLASSES],
    size_version: u64,
    tls_tags: [u64; TLS_TAGS],
    tls_epoch: u64,
}

impl MetadataState {
    fn new() -> Self {
        Self {
            thread: ThreadMetadataPayload {
                tid: 0xC0DE,
                generation: 1,
                flags: 0b1010_0101,
                stack_lo: 0x1000,
                stack_hi: 0x4000,
            },
            size_classes: std::array::from_fn(bin_size),
            size_version: 1,
            tls_tags: std::array::from_fn(|idx| 0x9E37_79B9_7F4A_7C15_u64 ^ idx as u64),
            tls_epoch: 1,
        }
    }
}

fn read_operation(state: &MetadataState, operation: MetadataOperation, cursor: usize) -> u64 {
    match operation {
        MetadataOperation::ThreadMetadata => {
            state.thread.tid
                ^ state.thread.generation
                ^ state.thread.flags
                ^ ((state.thread.stack_hi - state.thread.stack_lo) as u64)
                ^ cursor as u64
        }
        MetadataOperation::SizeClassLookup => {
            let idx = cursor % NUM_SIZE_CLASSES;
            state.size_classes[idx] as u64 ^ state.size_version
        }
        MetadataOperation::TlsCacheLookup => {
            let idx = cursor % TLS_TAGS;
            state.tls_tags[idx] ^ state.tls_epoch ^ idx as u64
        }
    }
}

fn write_operation(state: &mut MetadataState, operation: MetadataOperation, cursor: usize) {
    match operation {
        MetadataOperation::ThreadMetadata => {
            state.thread.generation = state.thread.generation.wrapping_add(1);
            state.thread.flags ^= 1_u64 << (cursor % 16);
            state.thread.stack_lo = state.thread.stack_lo.wrapping_add(16);
            state.thread.stack_hi = state.thread.stack_hi.wrapping_add(16);
        }
        MetadataOperation::SizeClassLookup => {
            state.size_version = state.size_version.wrapping_add(1);
        }
        MetadataOperation::TlsCacheLookup => {
            let idx = cursor % TLS_TAGS;
            state.tls_epoch = state.tls_epoch.wrapping_add(1);
            state.tls_tags[idx] = state.tls_tags[idx]
                .rotate_left(7)
                .wrapping_add(state.tls_epoch);
        }
    }
}

struct RcuMetadataCell {
    legacy: Mutex<MetadataState>,
    rcu: RcuDomain<MetadataState>,
}

impl RcuMetadataCell {
    fn new(initial: MetadataState) -> Self {
        let rcu = RcuDomain::new();
        let ptr = Box::into_raw(Box::new(initial.clone()));
        // SAFETY: `ptr` comes from `Box` and remains live until this wrapper
        // explicitly reclaims it after a grace period.
        unsafe {
            let _ = rcu.update(ptr);
        }
        Self {
            legacy: Mutex::new(initial),
            rcu,
        }
    }

    fn read_value(&self, tid: u32, operation: MetadataOperation, cursor: usize) -> u64 {
        rcu_read_lock();
        // SAFETY: the read-side critical section above protects the snapshot.
        let value = unsafe {
            self.rcu
                .read()
                .map(|state| read_operation(state, operation, cursor))
                .unwrap_or(0)
        };
        rcu_read_unlock();
        rcu_quiescent_state(tid);
        value
    }

    fn write(&self, tid: u32, operation: MetadataOperation, cursor: usize) {
        loop {
            // In QSBR, a thread waiting on the serialized writer mutex must keep
            // publishing quiescent progress so an active writer's grace-period
            // wait does not stall behind other would-be writers.
            rcu_quiescent_state(tid);
            match self.legacy.try_lock() {
                Ok(mut guard) => {
                    write_operation(&mut guard, operation, cursor);
                    let next_ptr = Box::into_raw(Box::new(guard.clone()));
                    // SAFETY: writers are serialized by `legacy`, so publishing
                    // the new pointer is exclusive.
                    let old_ptr = unsafe { self.rcu.update(next_ptr) };
                    drop(guard);
                    if !old_ptr.is_null() {
                        synchronize_rcu();
                        // SAFETY: `synchronize_rcu()` has completed, so no
                        // reader can still hold `old_ptr`.
                        unsafe {
                            drop(Box::from_raw(old_ptr));
                        }
                    }
                    rcu_quiescent_state(tid);
                    return;
                }
                Err(TryLockError::Poisoned(poisoned)) => {
                    let mut guard = poisoned.into_inner();
                    write_operation(&mut guard, operation, cursor);
                    let next_ptr = Box::into_raw(Box::new(guard.clone()));
                    // SAFETY: poisoned or not, this path still has exclusive
                    // access to the writer snapshot.
                    let old_ptr = unsafe { self.rcu.update(next_ptr) };
                    drop(guard);
                    if !old_ptr.is_null() {
                        synchronize_rcu();
                        // SAFETY: `synchronize_rcu()` has completed, so no
                        // reader can still hold `old_ptr`.
                        unsafe {
                            drop(Box::from_raw(old_ptr));
                        }
                    }
                    rcu_quiescent_state(tid);
                    return;
                }
                Err(TryLockError::WouldBlock) => thread::yield_now(),
            }
        }
    }
}

impl Drop for RcuMetadataCell {
    fn drop(&mut self) {
        // SAFETY: `drop` has exclusive access to the cell, and the benchmark has
        // already joined all worker threads before the wrapper is torn down.
        let old_ptr = unsafe { self.rcu.update(std::ptr::null_mut()) };
        if !old_ptr.is_null() {
            // SAFETY: no readers remain at process teardown for this wrapper.
            unsafe {
                drop(Box::from_raw(old_ptr));
            }
        }
    }
}

#[derive(Clone, Copy)]
struct BenchSettings {
    ops_per_thread: usize,
    trials: usize,
    sample_stride: usize,
}

impl BenchSettings {
    fn load() -> Self {
        let ops_per_thread = std::env::var("FRANKENLIBC_METADATA_BENCH_OPS_PER_THREAD")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_OPS_PER_THREAD)
            .max(100);
        let trials = std::env::var("FRANKENLIBC_METADATA_BENCH_TRIALS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_TRIALS)
            .max(1);
        let sample_stride = std::env::var("FRANKENLIBC_METADATA_BENCH_SAMPLE_STRIDE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_SAMPLE_STRIDE)
            .max(1);
        Self {
            ops_per_thread,
            trials,
            sample_stride,
        }
    }
}

#[derive(Default)]
struct WorkerResult {
    read_ops: u64,
    write_ops: u64,
    samples: Vec<u64>,
}

fn is_read_op(global_idx: usize, read_ratio_pct: u8) -> bool {
    (global_idx % 100) < read_ratio_pct as usize
}

fn run_rcu_trial(
    operation: MetadataOperation,
    read_ratio_pct: u8,
    thread_count: usize,
    settings: BenchSettings,
) -> MetadataBenchRecord {
    let shared = Arc::new(RcuMetadataCell::new(MetadataState::new()));
    let barrier = Arc::new(Barrier::new(thread_count + 1));
    let mut handles = Vec::with_capacity(thread_count);

    for worker_idx in 0..thread_count {
        let shared = Arc::clone(&shared);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let tid = (worker_idx + 1) as u32;
            let _ = rcu_register_thread(tid);
            barrier.wait();

            let mut result = WorkerResult::default();
            for op_idx in 0..settings.ops_per_thread {
                let global_idx = worker_idx * settings.ops_per_thread + op_idx;
                let read_op = is_read_op(global_idx, read_ratio_pct);
                let start = (op_idx % settings.sample_stride == 0).then(Instant::now);

                if read_op {
                    black_box(shared.read_value(tid, operation, global_idx));
                    result.read_ops += 1;
                } else {
                    shared.write(tid, operation, global_idx);
                    result.write_ops += 1;
                }

                if let Some(start) = start {
                    result
                        .samples
                        .push(start.elapsed().as_nanos().max(1) as u64);
                }
            }

            let _ = rcu_unregister_thread(tid);
            result
        }));
    }

    barrier.wait();
    let start = Instant::now();
    let mut read_ops = 0_u64;
    let mut write_ops = 0_u64;
    let mut samples = Vec::new();
    for handle in handles {
        let worker = handle.join().expect("rcu worker should join");
        read_ops += worker.read_ops;
        write_ops += worker.write_ops;
        samples.extend(worker.samples);
    }
    let elapsed = start.elapsed();

    let total_ops = read_ops + write_ops;
    let throughput_ops_s = total_ops as f64 / elapsed.as_secs_f64().max(1e-9);
    let (p50_ns_op, p95_ns_op, p99_ns_op, cv_pct) = summarize_latency_samples(&samples);

    MetadataBenchRecord {
        implementation: MetadataImplementation::Rcu,
        operation,
        read_ratio_pct,
        thread_count,
        total_ops,
        read_ops,
        write_ops,
        throughput_ops_s,
        p50_ns_op,
        p95_ns_op,
        p99_ns_op,
        cv_pct,
        sample_count: samples.len(),
    }
}

fn run_mutex_trial(
    operation: MetadataOperation,
    read_ratio_pct: u8,
    thread_count: usize,
    settings: BenchSettings,
) -> MetadataBenchRecord {
    let shared = Arc::new(Mutex::new(MetadataState::new()));
    let barrier = Arc::new(Barrier::new(thread_count + 1));
    let mut handles = Vec::with_capacity(thread_count);

    for worker_idx in 0..thread_count {
        let shared = Arc::clone(&shared);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();

            let mut result = WorkerResult::default();
            for op_idx in 0..settings.ops_per_thread {
                let global_idx = worker_idx * settings.ops_per_thread + op_idx;
                let read_op = is_read_op(global_idx, read_ratio_pct);
                let start = (op_idx % settings.sample_stride == 0).then(Instant::now);
                let mut guard = shared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());

                if read_op {
                    black_box(read_operation(&guard, operation, global_idx));
                    result.read_ops += 1;
                } else {
                    write_operation(&mut guard, operation, global_idx);
                    result.write_ops += 1;
                }
                drop(guard);

                if let Some(start) = start {
                    result
                        .samples
                        .push(start.elapsed().as_nanos().max(1) as u64);
                }
            }
            result
        }));
    }

    barrier.wait();
    let start = Instant::now();
    let mut read_ops = 0_u64;
    let mut write_ops = 0_u64;
    let mut samples = Vec::new();
    for handle in handles {
        let worker = handle.join().expect("mutex worker should join");
        read_ops += worker.read_ops;
        write_ops += worker.write_ops;
        samples.extend(worker.samples);
    }
    let elapsed = start.elapsed();

    let total_ops = read_ops + write_ops;
    let throughput_ops_s = total_ops as f64 / elapsed.as_secs_f64().max(1e-9);
    let (p50_ns_op, p95_ns_op, p99_ns_op, cv_pct) = summarize_latency_samples(&samples);

    MetadataBenchRecord {
        implementation: MetadataImplementation::Mutex,
        operation,
        read_ratio_pct,
        thread_count,
        total_ops,
        read_ops,
        write_ops,
        throughput_ops_s,
        p50_ns_op,
        p95_ns_op,
        p99_ns_op,
        cv_pct,
        sample_count: samples.len(),
    }
}

fn median_by_throughput(mut records: Vec<MetadataBenchRecord>) -> MetadataBenchRecord {
    records.sort_by(|lhs, rhs| {
        lhs.throughput_ops_s
            .partial_cmp(&rhs.throughput_ops_s)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    records.swap_remove(records.len() / 2)
}

fn run_matrix(settings: BenchSettings) -> Vec<MetadataBenchRecord> {
    let mut records =
        Vec::with_capacity(THREAD_COUNTS.len() * READ_RATIOS.len() * OPERATIONS.len() * 2);

    for operation in OPERATIONS {
        for read_ratio_pct in READ_RATIOS {
            for thread_count in THREAD_COUNTS {
                let rcu_trials = (0..settings.trials)
                    .map(|_| run_rcu_trial(operation, read_ratio_pct, thread_count, settings))
                    .collect::<Vec<_>>();
                let mutex_trials = (0..settings.trials)
                    .map(|_| run_mutex_trial(operation, read_ratio_pct, thread_count, settings))
                    .collect::<Vec<_>>();

                let rcu = median_by_throughput(rcu_trials);
                let mutex = median_by_throughput(mutex_trials);
                println!(
                    "METADATA_BENCH operation={} ratio={} threads={} rcu_ops_s={:.3} mutex_ops_s={:.3}",
                    operation.as_str(),
                    read_ratio_pct,
                    thread_count,
                    rcu.throughput_ops_s,
                    mutex.throughput_ops_s
                );
                records.push(rcu);
                records.push(mutex);
            }
        }
    }

    records
}

fn output_dir() -> PathBuf {
    std::env::var("FRANKENLIBC_METADATA_BENCH_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/metadata_read_bench"))
}

fn write_artifacts(records: &[MetadataBenchRecord], out_dir: &Path) -> std::io::Result<()> {
    let break_even = write_metadata_bench_artifacts(records, out_dir)?;
    println!(
        "METADATA_BENCH_SUMMARY records={} break_even_entries={} out_dir={}",
        records.len(),
        break_even.len(),
        out_dir.display()
    );
    Ok(())
}

fn bench_metadata_reads(_c: &mut Criterion) {
    if std::env::var("FRANKENLIBC_ENABLE_METADATA_BENCH")
        .ok()
        .as_deref()
        != Some("1")
    {
        println!("METADATA_BENCH_INFO skipped; set FRANKENLIBC_ENABLE_METADATA_BENCH=1 to run");
        return;
    }

    let settings = BenchSettings::load();
    let out_dir = output_dir();
    let records = run_matrix(settings);
    if let Err(err) = write_artifacts(&records, &out_dir) {
        eprintln!(
            "METADATA_BENCH_ERROR failed writing artifacts to {}: {err}",
            out_dir.display()
        );
    }
}

criterion_group!(metadata_benches, bench_metadata_reads);
criterion_main!(metadata_benches);
