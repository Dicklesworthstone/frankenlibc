//! Elimination-backoff benchmark and artifact emitter for bd-29j3.
//!
//! Runs an 8-thread symmetric handoff workload and compares the direct
//! elimination exchange path against a mutex-protected queue baseline.

use std::collections::VecDeque;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::malloc::{EliminationArray, OfferOutcome, TakeOutcome};

const THREADS: usize = 8;
const PRODUCERS: usize = THREADS / 2;
const CONSUMERS: usize = THREADS / 2;
const BENCH_SLOT_BIAS: usize = 7;
const DEFAULT_TRIALS: usize = 5;
const DEFAULT_OPS_PER_PRODUCER: usize = 40_000;
const DEFAULT_WAIT_BUDGET_US: u64 = 100;
const IMPROVEMENT_TARGET_PCT: f64 = 20.0;

#[derive(Clone, Copy)]
struct TrialConfig {
    ops_per_producer: usize,
    wait_budget: Duration,
}

#[derive(Clone)]
struct TrialResult {
    label: &'static str,
    throughput_ops_s: f64,
    elapsed_ns: u128,
    elimination_success_rate_ppm: Option<u32>,
}

struct Summary {
    elimination: TrialResult,
    mutex_queue: TrialResult,
    improvement_pct: f64,
    meets_target: bool,
}

fn trial_config() -> TrialConfig {
    let ops_per_producer = std::env::var("FRANKENLIBC_ELIMINATION_OPS_PER_PRODUCER")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_OPS_PER_PRODUCER);
    let wait_budget_us = std::env::var("FRANKENLIBC_ELIMINATION_WAIT_BUDGET_US")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_WAIT_BUDGET_US);
    TrialConfig {
        ops_per_producer,
        wait_budget: Duration::from_micros(wait_budget_us.max(1)),
    }
}

fn output_dir() -> PathBuf {
    std::env::var("FRANKENLIBC_ELIMINATION_BENCH_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/elimination_backoff"))
}

fn run_elimination_trial(config: TrialConfig) -> TrialResult {
    let queue = Arc::new(EliminationArray::<usize, 8>::with_wait_budget(
        config.wait_budget,
    ));
    let barrier = Arc::new(Barrier::new(THREADS + 1));
    let total_transfers = config.ops_per_producer * PRODUCERS;
    let consumer_target = total_transfers / CONSUMERS;
    let mut handles = Vec::with_capacity(THREADS);

    for producer_id in 0..PRODUCERS {
        let queue = Arc::clone(&queue);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for round in 0..config.ops_per_producer {
                let mut pending = producer_id * 1_000_000 + round;
                loop {
                    match queue.try_offer(BENCH_SLOT_BIAS, pending) {
                        OfferOutcome::Matched(_) => break,
                        OfferOutcome::Fallback { value, .. } => {
                            pending = value;
                            thread::yield_now();
                        }
                    }
                }
            }
        }));
    }

    for _consumer_id in 0..CONSUMERS {
        let queue = Arc::clone(&queue);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut received = 0usize;
            while received < consumer_target {
                match queue.try_take(BENCH_SLOT_BIAS) {
                    TakeOutcome::Matched { value, .. } => {
                        std::hint::black_box(value);
                        received += 1;
                    }
                    TakeOutcome::Fallback { .. } => thread::yield_now(),
                }
            }
        }));
    }

    barrier.wait();
    let start = Instant::now();
    for handle in handles {
        handle.join().expect("elimination worker joins");
    }
    let elapsed = start.elapsed();
    let total_ops = (total_transfers * 2) as f64;
    let elapsed_secs = elapsed.as_secs_f64().max(1e-9);

    TrialResult {
        label: "elimination",
        throughput_ops_s: total_ops / elapsed_secs,
        elapsed_ns: elapsed.as_nanos(),
        elimination_success_rate_ppm: Some(queue.stats().success_rate_ppm),
    }
}

fn run_mutex_queue_trial(config: TrialConfig) -> TrialResult {
    let queue = Arc::new(Mutex::new(VecDeque::<usize>::new()));
    let barrier = Arc::new(Barrier::new(THREADS + 1));
    let total_transfers = config.ops_per_producer * PRODUCERS;
    let consumer_target = total_transfers / CONSUMERS;
    let mut handles = Vec::with_capacity(THREADS);

    for producer_id in 0..PRODUCERS {
        let queue = Arc::clone(&queue);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for round in 0..config.ops_per_producer {
                let value = producer_id * 1_000_000 + round;
                let mut guard = queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                guard.push_back(value);
            }
        }));
    }

    for _consumer_id in 0..CONSUMERS {
        let queue = Arc::clone(&queue);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut received = 0usize;
            while received < consumer_target {
                let mut guard = queue
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(value) = guard.pop_front() {
                    drop(guard);
                    std::hint::black_box(value);
                    received += 1;
                } else {
                    drop(guard);
                    thread::yield_now();
                }
            }
        }));
    }

    barrier.wait();
    let start = Instant::now();
    for handle in handles {
        handle.join().expect("mutex queue worker joins");
    }
    let elapsed = start.elapsed();
    let total_ops = (total_transfers * 2) as f64;
    let elapsed_secs = elapsed.as_secs_f64().max(1e-9);

    TrialResult {
        label: "mutex_queue",
        throughput_ops_s: total_ops / elapsed_secs,
        elapsed_ns: elapsed.as_nanos(),
        elimination_success_rate_ppm: None,
    }
}

fn median_by_throughput(mut trials: Vec<TrialResult>) -> TrialResult {
    trials.sort_by(|a, b| {
        a.throughput_ops_s
            .partial_cmp(&b.throughput_ops_s)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    trials[trials.len() / 2].clone()
}

fn run_summary() -> Summary {
    let config = trial_config();
    let trials = std::env::var("FRANKENLIBC_ELIMINATION_TRIALS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TRIALS)
        .max(1);

    let elimination_trials = (0..trials)
        .map(|_| run_elimination_trial(config))
        .collect::<Vec<_>>();
    let mutex_trials = (0..trials)
        .map(|_| run_mutex_queue_trial(config))
        .collect::<Vec<_>>();

    let elimination = median_by_throughput(elimination_trials);
    let mutex_queue = median_by_throughput(mutex_trials);
    let improvement_pct = if mutex_queue.throughput_ops_s <= f64::EPSILON {
        0.0
    } else {
        ((elimination.throughput_ops_s - mutex_queue.throughput_ops_s)
            / mutex_queue.throughput_ops_s)
            * 100.0
    };

    Summary {
        elimination,
        mutex_queue,
        improvement_pct,
        meets_target: improvement_pct >= IMPROVEMENT_TARGET_PCT,
    }
}

fn write_summary(summary: &Summary, out_dir: &Path) -> std::io::Result<()> {
    let mut file = File::create(out_dir.join("elimination_benchmark.json"))?;
    let generated_unix_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    writeln!(file, "{{")?;
    writeln!(file, "  \"schema_version\": 1,")?;
    writeln!(file, "  \"bead_id\": \"bd-29j3\",")?;
    writeln!(file, "  \"generated_unix_ts\": {generated_unix_ts},")?;
    writeln!(file, "  \"thread_count\": {THREADS},")?;
    writeln!(file, "  \"producer_count\": {PRODUCERS},")?;
    writeln!(file, "  \"consumer_count\": {CONSUMERS},")?;
    writeln!(
        file,
        "  \"improvement_target_pct\": {:.3},",
        IMPROVEMENT_TARGET_PCT
    )?;
    writeln!(
        file,
        "  \"improvement_pct\": {:.3},",
        summary.improvement_pct
    )?;
    writeln!(file, "  \"meets_target\": {},", summary.meets_target)?;
    writeln!(file, "  \"records\": [")?;
    for (idx, record) in [summary.elimination.clone(), summary.mutex_queue.clone()]
        .into_iter()
        .enumerate()
    {
        let comma = if idx == 0 { "," } else { "" };
        match record.elimination_success_rate_ppm {
            Some(success_rate_ppm) => {
                writeln!(
                    file,
                    "    {{\"label\":\"{}\",\"throughput_ops_s\":{:.3},\"elapsed_ns\":{},\"elimination_success_rate_ppm\":{}}}{}",
                    record.label,
                    record.throughput_ops_s,
                    record.elapsed_ns,
                    success_rate_ppm,
                    comma
                )?;
            }
            None => {
                writeln!(
                    file,
                    "    {{\"label\":\"{}\",\"throughput_ops_s\":{:.3},\"elapsed_ns\":{},\"elimination_success_rate_ppm\":null}}{}",
                    record.label, record.throughput_ops_s, record.elapsed_ns, comma
                )?;
            }
        }
    }
    writeln!(file, "  ]")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn bench_elimination_backoff(_c: &mut Criterion) {
    if std::env::var("FRANKENLIBC_ENABLE_ELIMINATION_BENCH")
        .ok()
        .as_deref()
        != Some("1")
    {
        println!(
            "ELIMINATION_BENCH_INFO skipped; set FRANKENLIBC_ENABLE_ELIMINATION_BENCH=1 to run"
        );
        return;
    }

    let out_dir = output_dir();
    if let Err(err) = create_dir_all(&out_dir) {
        eprintln!(
            "ELIMINATION_BENCH_ERROR could not create output dir {}: {err}",
            out_dir.display()
        );
        return;
    }

    let summary = run_summary();
    if let Err(err) = write_summary(&summary, &out_dir) {
        eprintln!("ELIMINATION_BENCH_ERROR failed writing summary artifact: {err}");
        return;
    }

    println!(
        "ELIMINATION_BENCH_SUMMARY elimination_ops_s={:.3} mutex_queue_ops_s={:.3} improvement_pct={:.3} meets_target={} output_dir={}",
        summary.elimination.throughput_ops_s,
        summary.mutex_queue.throughput_ops_s,
        summary.improvement_pct,
        summary.meets_target,
        out_dir.display()
    );
}

criterion_group!(benches, bench_elimination_backoff);
criterion_main!(benches);
