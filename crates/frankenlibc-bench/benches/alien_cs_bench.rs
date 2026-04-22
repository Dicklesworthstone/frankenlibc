//! Benchmarks for Alien CS concurrency primitives.
//!
//! Measures per-operation overhead for RCU, SeqLock, EBR, and Flat Combining
//! at varying thread counts. Establishes performance budgets and tracks regressions.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_membrane::bravo::BravoRwLock;
use frankenlibc_membrane::ebr::EbrCollector;
use frankenlibc_membrane::flat_combining::FlatCombiner;
use frankenlibc_membrane::left_right::LeftRight;
use frankenlibc_membrane::rcu::{RcuCell, RcuReader};
use frankenlibc_membrane::seqlock::{SeqLock, SeqLockReader};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ──────────────── RCU read hot path ────────────────

fn bench_rcu_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("rcu_read");

    // Single-thread read (baseline).
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_thread", |b| {
        let cell = RcuCell::new(42u64);
        let mut reader = RcuReader::new(&cell);
        b.iter(|| {
            black_box(*reader.read());
        });
    });

    // Multi-thread read contention.
    for n_threads in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_readers", n_threads),
            &n_threads,
            |b, &n| {
                let cell = Arc::new(RcuCell::new(42u64));
                let barrier = Arc::new(Barrier::new(n + 1));
                let done = Arc::new(AtomicBool::new(false));

                let handles: Vec<_> = (0..n)
                    .map(|_| {
                        let cell = Arc::clone(&cell);
                        let barrier = Arc::clone(&barrier);
                        let done = Arc::clone(&done);
                        thread::spawn(move || {
                            let mut reader = RcuReader::new(&cell);
                            barrier.wait();
                            while !done.load(Ordering::Relaxed) {
                                black_box(*reader.read());
                            }
                        })
                    })
                    .collect();

                barrier.wait();
                b.iter(|| {
                    black_box(*cell.load());
                });
                done.store(true, Ordering::Relaxed);

                for h in handles {
                    h.join().unwrap();
                }
            },
        );
    }
    group.finish();
}

// ──────────────── RCU update ────────────────

fn bench_rcu_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("rcu_update");
    group.throughput(Throughput::Elements(1));

    group.bench_function("single_thread", |b| {
        let cell = RcuCell::new(0u64);
        let mut val = 0u64;
        b.iter(|| {
            val += 1;
            cell.update(black_box(val));
        });
    });
    group.finish();
}

// ──────────────── BRAVO read hot path ────────────────

fn bench_bravo_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("bravo_read");

    group.throughput(Throughput::Elements(1));
    group.bench_function("single_thread", |b| {
        let lock = BravoRwLock::new(42_u64);
        b.iter(|| {
            let guard = lock.read();
            black_box(*guard);
        });
    });

    for n_threads in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_readers", n_threads),
            &n_threads,
            |b, &n| {
                let lock = Arc::new(BravoRwLock::new(42_u64));
                let barrier = Arc::new(Barrier::new(n + 1));
                let done = Arc::new(AtomicBool::new(false));

                let handles: Vec<_> = (0..n)
                    .map(|_| {
                        let lock = Arc::clone(&lock);
                        let barrier = Arc::clone(&barrier);
                        let done = Arc::clone(&done);
                        thread::spawn(move || {
                            barrier.wait();
                            while !done.load(Ordering::Relaxed) {
                                let guard = lock.read();
                                black_box(*guard);
                            }
                        })
                    })
                    .collect();

                barrier.wait();
                b.iter(|| {
                    let guard = lock.read();
                    black_box(*guard);
                });
                done.store(true, Ordering::Relaxed);

                for handle in handles {
                    handle.join().unwrap();
                }
            },
        );
    }

    group.finish();
}

// ──────────────── SeqLock read hot path ────────────────

fn bench_seqlock_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("seqlock_read");

    // Single-thread cached read (best case).
    group.throughput(Throughput::Elements(1));
    group.bench_function("cached_single_thread", |b| {
        let sl = SeqLock::new(42u64);
        let mut reader = SeqLockReader::new(&sl);
        // Prime cache.
        let _ = reader.read();
        b.iter(|| {
            black_box(*reader.read());
        });
    });

    // Read after write (cache miss path).
    group.bench_function("miss_after_write", |b| {
        let sl = SeqLock::new(0u64);
        let mut reader = SeqLockReader::new(&sl);
        let mut val = 0u64;
        b.iter(|| {
            val += 1;
            sl.write_with(|d| *d = val);
            black_box(*reader.read());
        });
    });

    // Multi-thread reads.
    for n_threads in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_readers", n_threads),
            &n_threads,
            |b, &n| {
                let sl = Arc::new(SeqLock::new(42u64));
                let barrier = Arc::new(Barrier::new(n + 1));
                let done = Arc::new(AtomicBool::new(false));

                let handles: Vec<_> = (0..n)
                    .map(|_| {
                        let sl = Arc::clone(&sl);
                        let barrier = Arc::clone(&barrier);
                        let done = Arc::clone(&done);
                        thread::spawn(move || {
                            let mut reader = SeqLockReader::new(&sl);
                            barrier.wait();
                            while !done.load(Ordering::Relaxed) {
                                black_box(*reader.read());
                            }
                        })
                    })
                    .collect();

                barrier.wait();
                b.iter(|| {
                    black_box(*sl.load());
                });
                done.store(true, Ordering::Relaxed);

                for h in handles {
                    h.join().unwrap();
                }
            },
        );
    }
    group.finish();
}

// ──────────────── SeqLock write ────────────────

fn bench_seqlock_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("seqlock_write");
    group.throughput(Throughput::Elements(1));

    group.bench_function("write_with", |b| {
        let sl = SeqLock::new(0u64);
        let mut val = 0u64;
        b.iter(|| {
            val += 1;
            sl.write_with(|d| *d = black_box(val));
        });
    });

    group.bench_function("batched_5_mutations", |b| {
        let sl = SeqLock::new(0u64);
        b.iter(|| {
            let mut guard = sl.write();
            for _ in 0..5 {
                guard.mutate(|d| *d += 1);
            }
        });
    });
    group.finish();
}

// ──────────────── EBR pin/unpin ────────────────

fn bench_ebr_pin(c: &mut Criterion) {
    let mut group = c.benchmark_group("ebr_pin");
    group.throughput(Throughput::Elements(1));

    group.bench_function("pin_unpin", |b| {
        let collector = EbrCollector::new();
        let handle = collector.register();
        b.iter(|| {
            let guard = handle.pin();
            black_box(guard.epoch());
            drop(guard);
        });
    });

    group.bench_function("pin_retire_unpin", |b| {
        let collector = EbrCollector::new();
        let handle = collector.register();
        b.iter(|| {
            let guard = handle.pin();
            guard.retire(|| {});
            drop(guard);
            collector.try_advance();
        });
    });
    group.finish();
}

// ──────────────── EBR retire + advance ────────────────

fn bench_ebr_retire(c: &mut Criterion) {
    let mut group = c.benchmark_group("ebr_retire");
    group.throughput(Throughput::Elements(1));

    group.bench_function("retire_only", |b| {
        let collector = EbrCollector::new();
        b.iter(|| {
            collector.retire(|| {});
        });
    });

    group.bench_function("advance", |b| {
        let collector = EbrCollector::new();
        // Pre-fill some items.
        for _ in 0..100 {
            collector.retire(|| {});
        }
        b.iter(|| {
            collector.try_advance();
        });
    });
    group.finish();
}

// ──────────────── Flat Combining ────────────────

fn bench_flat_combining(c: &mut Criterion) {
    let mut group = c.benchmark_group("flat_combining");

    // Single-thread (no combining benefit, measures lock overhead).
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_thread_increment", |b| {
        let fc = FlatCombiner::new(0u64, 4);
        b.iter(|| {
            fc.execute(1u64, |s, o| {
                *s += o;
                black_box(*s)
            });
        });
    });

    // Multi-thread combining.
    for n_threads in [2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_increment", n_threads),
            &n_threads,
            |b, &n| {
                let fc = Arc::new(FlatCombiner::new(0u64, n.max(4)));
                let barrier = Arc::new(Barrier::new(n + 1));
                let done = Arc::new(AtomicBool::new(false));

                let handles: Vec<_> = (0..n)
                    .map(|_| {
                        let fc = Arc::clone(&fc);
                        let barrier = Arc::clone(&barrier);
                        let done = Arc::clone(&done);
                        thread::spawn(move || {
                            barrier.wait();
                            while !done.load(Ordering::Relaxed) {
                                fc.execute(1u64, |s, o| {
                                    *s += o;
                                    *s
                                });
                            }
                        })
                    })
                    .collect();

                barrier.wait();
                b.iter(|| {
                    fc.execute(1u64, |s, o| {
                        *s += o;
                        black_box(*s)
                    });
                });
                done.store(true, Ordering::Relaxed);

                for h in handles {
                    h.join().unwrap();
                }
            },
        );
    }
    group.finish();
}

// ──────────────── Metadata comparison ────────────────

fn bench_metadata_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_read_comparison");
    group.throughput(Throughput::Elements(1));

    let seeded = seed_metadata();
    let keys: Vec<_> = (0..1024).map(|idx| idx & 255).collect();

    group.bench_function("bravo", |b| {
        let lock = BravoRwLock::new(seeded.clone());
        let mut idx = 0usize;
        b.iter(|| {
            let guard = lock.read();
            black_box(guard.get(&keys[idx & 1023]).copied().unwrap_or_default());
            idx = idx.wrapping_add(1);
        });
    });

    group.bench_function("rcu", |b| {
        let cell = RcuCell::new(seeded.clone());
        let mut reader = RcuReader::new(&cell);
        let mut idx = 0usize;
        b.iter(|| {
            black_box(
                reader
                    .read()
                    .get(&keys[idx & 1023])
                    .copied()
                    .unwrap_or_default(),
            );
            idx = idx.wrapping_add(1);
        });
    });

    group.bench_function("left_right", |b| {
        let lock = LeftRight::new(seeded.clone());
        let mut reader = lock.reader();
        let mut idx = 0usize;
        b.iter(|| {
            black_box(
                reader
                    .read()
                    .get(&keys[idx & 1023])
                    .copied()
                    .unwrap_or_default(),
            );
            idx = idx.wrapping_add(1);
        });
    });

    group.finish();
}

// ──────────────── Composite pipeline ────────────────

fn bench_composite_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("composite_pipeline");
    group.throughput(Throughput::Elements(1));

    // Simulates the hot path: SeqLock read + RCU read + FC execute.
    group.bench_function("seqlock_rcu_fc", |b| {
        let config = SeqLock::new(42u64);
        let state = RcuCell::new(0u64);
        let metrics = FlatCombiner::new(0u64, 4);

        let mut cfg_reader = SeqLockReader::new(&config);
        let mut state_reader = RcuReader::new(&state);

        b.iter(|| {
            let cfg = black_box(*cfg_reader.read());
            let snap = black_box(*state_reader.read());
            let _ = metrics.execute(1u64, |s, o| {
                *s += o;
                *s
            });
            black_box(cfg + snap);
        });
    });

    // Full pipeline with EBR pin.
    group.bench_function("full_with_ebr", |b| {
        let config = SeqLock::new(42u64);
        let state = RcuCell::new(0u64);
        let metrics = FlatCombiner::new(0u64, 4);
        let collector = EbrCollector::new();
        let handle = collector.register();

        let mut cfg_reader = SeqLockReader::new(&config);
        let mut state_reader = RcuReader::new(&state);

        b.iter(|| {
            let guard = handle.pin();
            let cfg = black_box(*cfg_reader.read());
            let snap = black_box(*state_reader.read());
            let _ = metrics.execute(1u64, |s, o| {
                *s += o;
                *s
            });
            drop(guard);
            black_box(cfg + snap);
        });
    });
    group.finish();
}

fn seed_metadata() -> HashMap<usize, u64> {
    (0..256).map(|idx| (idx, idx as u64)).collect()
}

criterion_group!(
    benches,
    bench_rcu_read,
    bench_rcu_update,
    bench_bravo_read,
    bench_seqlock_read,
    bench_seqlock_write,
    bench_ebr_pin,
    bench_ebr_retire,
    bench_flat_combining,
    bench_metadata_comparison,
    bench_composite_pipeline,
);
criterion_main!(benches);
