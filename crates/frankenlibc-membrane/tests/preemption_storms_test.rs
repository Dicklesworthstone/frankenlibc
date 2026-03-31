use frankenlibc_membrane::ValidationOutcome;
use frankenlibc_membrane::ValidationPipeline;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

const THREADS_RELEASE: usize = 128;
const THREADS_DEBUG: usize = 48;
const ITERS_RELEASE: usize = 512;
const ITERS_DEBUG: usize = 128;
const SAMPLE_STRIDE_RELEASE: usize = 8;
const SAMPLE_STRIDE_DEBUG: usize = 4;
const TIMEOUT_SECONDS: u64 = 30;
const STALL_BUDGET_MS: u64 = 1_000;
static SIGUSR1_INSTALL: Once = Once::new();
static SIGUSR1_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
enum StormType {
    QuantumYield,
    SignalJitter,
    AffinityCollapse,
    PriorityInversion,
    ThunderingHerd,
}

impl StormType {
    fn as_str(self) -> &'static str {
        match self {
            StormType::QuantumYield => "quantum_yield",
            StormType::SignalJitter => "signal_jitter",
            StormType::AffinityCollapse => "affinity_collapse",
            StormType::PriorityInversion => "priority_inversion",
            StormType::ThunderingHerd => "thundering_herd",
        }
    }

    fn all() -> [Self; 5] {
        [
            Self::QuantumYield,
            Self::SignalJitter,
            Self::AffinityCollapse,
            Self::PriorityInversion,
            Self::ThunderingHerd,
        ]
    }
}

#[derive(Debug, Default)]
struct ThreadStats {
    ops_completed: usize,
    allocations: usize,
    frees: usize,
    corruption_events: usize,
    sampled_latencies_ns: Vec<u64>,
    max_hold_ns: u64,
    rr_applied: bool,
    affinity_applied: bool,
}

#[derive(Debug)]
struct MonitorStats {
    deadlock_detected: bool,
    max_progress_gap_ms: u64,
}

#[derive(Debug)]
struct StormReport {
    storm_type: &'static str,
    thread_count: usize,
    iterations_per_thread: usize,
    completion_time_ms: u64,
    deadlock_detected: bool,
    corruption_detected: bool,
    ops_completed: usize,
    allocations: usize,
    frees: usize,
    p99_latency_ns: u64,
    baseline_p99_ns: u64,
    p99_ratio_x1000: u64,
    max_hold_ns: u64,
    max_progress_gap_ms: u64,
    signals_observed: u64,
    rr_threads_applied: usize,
    affinity_threads_applied: usize,
}

#[allow(unsafe_code)]
unsafe extern "C" fn record_sigusr1(_sig: libc::c_int) {
    SIGUSR1_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn current_mode_name() -> &'static str {
    use frankenlibc_membrane::config::{safety_level, SafetyLevel};
    match safety_level() {
        SafetyLevel::Off => "off",
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
    }
}

fn storm_artifact_paths(mode: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from("target/preemption_storms");
    fs::create_dir_all(&dir).expect("must create preemption-storm artifact directory");
    (
        dir.join(format!("bd-18qq.3_preemption_storm_report_{mode}.json")),
        dir.join(format!("bd-18qq.3_preemption_storm_trace_{mode}.jsonl")),
    )
}

fn write_json_artifact(path: &PathBuf, payload: &Value) {
    let encoded =
        serde_json::to_string_pretty(payload).expect("preemption payload must serialize to JSON");
    fs::write(path, encoded).expect("preemption JSON artifact must be writable");
}

fn write_jsonl_artifact(path: &PathBuf, rows: &[Value]) {
    let mut out = String::new();
    for row in rows {
        let line = serde_json::to_string(row).expect("preemption JSONL row must serialize");
        out.push_str(&line);
        out.push('\n');
    }
    fs::write(path, out).expect("preemption JSONL artifact must be writable");
}

fn percentile_ns(values: &mut [u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let idx = ((values.len() - 1) * percentile) / 100;
    let (_, nth, _) = values.select_nth_unstable(idx);
    *nth
}

fn sample_stride() -> usize {
    if cfg!(debug_assertions) {
        SAMPLE_STRIDE_DEBUG
    } else {
        SAMPLE_STRIDE_RELEASE
    }
}

fn iterations_per_thread() -> usize {
    if cfg!(debug_assertions) {
        ITERS_DEBUG
    } else {
        ITERS_RELEASE
    }
}

fn thread_count() -> usize {
    if cfg!(debug_assertions) {
        THREADS_DEBUG
    } else {
        THREADS_RELEASE
    }
}

fn baseline_p99_ns(iterations: usize, workers: usize) -> u64 {
    let pipeline = Arc::new(ValidationPipeline::new());
    let mut joins = Vec::with_capacity(workers);
    for worker_idx in 0..workers {
        let pipeline = Arc::clone(&pipeline);
        joins.push(thread::spawn(move || {
            let mut samples = Vec::with_capacity(iterations / sample_stride().max(1));
            for iter in 0..iterations {
                let (ok, latency_ns) = perform_allocator_roundtrip(&pipeline, worker_idx, iter);
                assert!(ok, "baseline roundtrip must succeed");
                if iter % sample_stride() == 0 {
                    samples.push(latency_ns);
                }
            }
            samples
        }));
    }

    let mut samples = Vec::new();
    for join in joins {
        samples.extend(join.join().expect("baseline worker must not panic"));
    }
    percentile_ns(&mut samples, 99).max(1)
}

fn install_sigusr1_handler() {
    SIGUSR1_INSTALL.call_once(|| {
        #[allow(unsafe_code)]
        unsafe {
            let mut action = std::mem::zeroed::<libc::sigaction>();
            action.sa_flags = 0;
            action.sa_sigaction = record_sigusr1 as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            let rc = libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut());
            assert_eq!(rc, 0, "SIGUSR1 handler installation must succeed");
        }
    });
}

fn wait_briefly() {
    thread::sleep(Duration::from_micros(10));
}

#[allow(unsafe_code)]
fn try_pin_current_thread(core: usize) -> bool {
    unsafe {
        let mut set = std::mem::zeroed::<libc::cpu_set_t>();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) == 0
    }
}

#[allow(unsafe_code)]
fn try_set_round_robin(priority: i32) -> bool {
    unsafe {
        let param = libc::sched_param {
            sched_priority: priority,
        };
        libc::pthread_setschedparam(libc::pthread_self(), libc::SCHED_RR, &param) == 0
    }
}

fn perform_allocator_roundtrip(
    pipeline: &ValidationPipeline,
    worker_idx: usize,
    iter: usize,
) -> (bool, u64) {
    let size = 32 + ((worker_idx * 131 + iter * 17) % 2048);
    let start = Instant::now();
    let Some(ptr) = pipeline.allocate(size) else {
        return (false, start.elapsed().as_nanos() as u64);
    };
    let out = pipeline.validate(ptr as usize);
    let valid = matches!(
        out,
        ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
    );
    let free_ok = matches!(
        pipeline.free(ptr),
        frankenlibc_membrane::arena::FreeResult::Freed
            | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption
    );
    (valid && free_ok, start.elapsed().as_nanos() as u64)
}

fn monitor_progress(
    progress: Arc<AtomicUsize>,
    done_workers: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    worker_count: usize,
) -> MonitorStats {
    let timeout = Duration::from_secs(TIMEOUT_SECONDS);
    let started = Instant::now();
    let mut last_progress = progress.load(Ordering::Relaxed);
    let mut stalled_since = Instant::now();
    let mut max_gap_ms = 0_u64;

    loop {
        if done_workers.load(Ordering::Relaxed) == worker_count {
            return MonitorStats {
                deadlock_detected: false,
                max_progress_gap_ms: max_gap_ms,
            };
        }
        if started.elapsed() > timeout {
            cancel.store(true, Ordering::Relaxed);
            return MonitorStats {
                deadlock_detected: true,
                max_progress_gap_ms: max_gap_ms.max(stalled_since.elapsed().as_millis() as u64),
            };
        }
        thread::sleep(Duration::from_millis(100));
        let current = progress.load(Ordering::Relaxed);
        if current == last_progress {
            max_gap_ms = max_gap_ms.max(stalled_since.elapsed().as_millis() as u64);
        } else {
            last_progress = current;
            stalled_since = Instant::now();
        }
    }
}

fn run_generic_storm(
    storm: StormType,
    pipeline: Arc<ValidationPipeline>,
    iterations: usize,
    workers: usize,
) -> StormReport {
    let progress = Arc::new(AtomicUsize::new(0));
    let done_workers = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let herd_barrier = Arc::new(Barrier::new(workers));
    let rr_applied = Arc::new(AtomicUsize::new(0));
    let affinity_applied = Arc::new(AtomicUsize::new(0));
    let signals_before = SIGUSR1_COUNT.load(Ordering::Relaxed);
    if matches!(storm, StormType::SignalJitter) {
        install_sigusr1_handler();
    }

    let started = Instant::now();
    let mut joins = Vec::with_capacity(workers);
    for worker_idx in 0..workers {
        let pipeline = Arc::clone(&pipeline);
        let progress = Arc::clone(&progress);
        let done_workers = Arc::clone(&done_workers);
        let cancel = Arc::clone(&cancel);
        let herd_barrier = Arc::clone(&herd_barrier);
        let rr_applied_ctr = Arc::clone(&rr_applied);
        let affinity_applied_ctr = Arc::clone(&affinity_applied);
        joins.push(thread::spawn(move || {
            let mut stats = ThreadStats::default();
            if matches!(storm, StormType::AffinityCollapse)
                && try_pin_current_thread(worker_idx % 2)
            {
                stats.affinity_applied = true;
                affinity_applied_ctr.fetch_add(1, Ordering::Relaxed);
            }
            if matches!(storm, StormType::PriorityInversion) {
                let priority = if worker_idx == 0 {
                    1
                } else if worker_idx < workers / 3 {
                    20
                } else {
                    10
                };
                if try_set_round_robin(priority) {
                    stats.rr_applied = true;
                    rr_applied_ctr.fetch_add(1, Ordering::Relaxed);
                }
            }

            for iter in 0..iterations {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                match storm {
                    StormType::QuantumYield => {
                        thread::yield_now();
                        wait_briefly();
                    }
                    StormType::SignalJitter => {
                        if worker_idx == 0 && iter % 4 == 0 {
                            #[allow(unsafe_code)]
                            unsafe {
                                libc::kill(libc::getpid(), libc::SIGUSR1);
                            }
                        }
                        if iter % 2 == 0 {
                            thread::yield_now();
                        }
                    }
                    StormType::AffinityCollapse => {
                        if !stats.affinity_applied && iter % 2 == 0 {
                            thread::yield_now();
                        }
                    }
                    StormType::PriorityInversion => {
                        if worker_idx >= workers / 3 {
                            for _ in 0..8 {
                                std::hint::spin_loop();
                            }
                        }
                    }
                    StormType::ThunderingHerd => {
                        herd_barrier.wait();
                    }
                }

                let hold_started = Instant::now();
                let (ok, latency_ns) = perform_allocator_roundtrip(&pipeline, worker_idx, iter);
                stats.max_hold_ns = stats
                    .max_hold_ns
                    .max(hold_started.elapsed().as_nanos() as u64);
                stats.ops_completed += 1;
                stats.allocations += 1;
                stats.frees += 1;
                if !ok {
                    stats.corruption_events += 1;
                }
                if iter % sample_stride() == 0 {
                    stats.sampled_latencies_ns.push(latency_ns);
                }
                progress.fetch_add(1, Ordering::Relaxed);
            }
            done_workers.fetch_add(1, Ordering::Relaxed);
            stats
        }));
    }

    let monitor = monitor_progress(
        Arc::clone(&progress),
        Arc::clone(&done_workers),
        Arc::clone(&cancel),
        workers,
    );

    let mut all_latencies = Vec::new();
    let mut ops_completed = 0_usize;
    let mut allocations = 0_usize;
    let mut frees = 0_usize;
    let mut corruption_events = 0_usize;
    let mut max_hold_ns = 0_u64;
    for join in joins {
        let stats = join.join().expect("worker thread must not panic");
        all_latencies.extend(stats.sampled_latencies_ns);
        ops_completed += stats.ops_completed;
        allocations += stats.allocations;
        frees += stats.frees;
        corruption_events += stats.corruption_events;
        max_hold_ns = max_hold_ns.max(stats.max_hold_ns);
    }

    let completion_time_ms = started.elapsed().as_millis() as u64;
    let baseline_p99 = baseline_p99_ns((iterations / 2).max(256), workers);
    let p99_latency_ns = percentile_ns(&mut all_latencies, 99);
    let p99_ratio_x1000 =
        ((p99_latency_ns.max(1) as u128 * 1000) / baseline_p99.max(1) as u128) as u64;

    StormReport {
        storm_type: storm.as_str(),
        thread_count: workers,
        iterations_per_thread: iterations,
        completion_time_ms,
        deadlock_detected: monitor.deadlock_detected,
        corruption_detected: corruption_events > 0,
        ops_completed,
        allocations,
        frees,
        p99_latency_ns,
        baseline_p99_ns: baseline_p99,
        p99_ratio_x1000,
        max_hold_ns,
        max_progress_gap_ms: monitor.max_progress_gap_ms,
        signals_observed: SIGUSR1_COUNT
            .load(Ordering::Relaxed)
            .saturating_sub(signals_before),
        rr_threads_applied: rr_applied.load(Ordering::Relaxed),
        affinity_threads_applied: affinity_applied.load(Ordering::Relaxed),
    }
}

fn run_priority_inversion_storm(
    pipeline: Arc<ValidationPipeline>,
    iterations: usize,
    workers: usize,
) -> StormReport {
    let progress = Arc::new(AtomicUsize::new(0));
    let done_workers = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(Mutex::new(()));
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let rr_applied = Arc::new(AtomicUsize::new(0));
    let started = Instant::now();

    let mut joins = Vec::with_capacity(workers);
    for worker_idx in 0..workers {
        let pipeline = Arc::clone(&pipeline);
        let progress = Arc::clone(&progress);
        let done_workers = Arc::clone(&done_workers);
        let cancel = Arc::clone(&cancel);
        let gate = Arc::clone(&gate);
        let pair = Arc::clone(&pair);
        let rr_applied_ctr = Arc::clone(&rr_applied);
        joins.push(thread::spawn(move || {
            let mut stats = ThreadStats::default();
            let priority = if worker_idx == 0 {
                1
            } else if worker_idx < workers / 3 {
                20
            } else {
                10
            };
            if try_set_round_robin(priority) {
                stats.rr_applied = true;
                rr_applied_ctr.fetch_add(1, Ordering::Relaxed);
            }

            if worker_idx == 0 {
                {
                    let (started_flag, cvar) = &*pair;
                    let mut started_flag = started_flag.lock().expect("flag mutex");
                    *started_flag = true;
                    cvar.notify_all();
                }
                for iter in 0..iterations {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let critical = Instant::now();
                    let _guard = gate.lock().expect("priority inversion gate");
                    wait_briefly();
                    let (ok, latency_ns) = perform_allocator_roundtrip(&pipeline, worker_idx, iter);
                    stats.max_hold_ns = stats.max_hold_ns.max(critical.elapsed().as_nanos() as u64);
                    stats.ops_completed += 1;
                    stats.allocations += 1;
                    stats.frees += 1;
                    if !ok {
                        stats.corruption_events += 1;
                    }
                    if iter % sample_stride() == 0 {
                        stats.sampled_latencies_ns.push(latency_ns);
                    }
                    progress.fetch_add(1, Ordering::Relaxed);
                }
            } else if worker_idx < workers / 3 {
                let (started_flag, cvar) = &*pair;
                let mut ready = started_flag.lock().expect("flag mutex");
                while !*ready {
                    ready = cvar.wait(ready).expect("condvar wait");
                }
                drop(ready);
                for iter in 0..iterations {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let critical = Instant::now();
                    let _guard = gate.lock().expect("priority inversion gate");
                    let (ok, latency_ns) = perform_allocator_roundtrip(&pipeline, worker_idx, iter);
                    stats.max_hold_ns = stats.max_hold_ns.max(critical.elapsed().as_nanos() as u64);
                    stats.ops_completed += 1;
                    stats.allocations += 1;
                    stats.frees += 1;
                    if !ok {
                        stats.corruption_events += 1;
                    }
                    if iter % sample_stride() == 0 {
                        stats.sampled_latencies_ns.push(latency_ns);
                    }
                    progress.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                for _ in 0..(iterations * 16) {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    std::hint::spin_loop();
                    if worker_idx % 4 == 0 {
                        thread::yield_now();
                    }
                }
            }

            done_workers.fetch_add(1, Ordering::Relaxed);
            stats
        }));
    }

    let monitor = monitor_progress(
        Arc::clone(&progress),
        Arc::clone(&done_workers),
        Arc::clone(&cancel),
        workers,
    );

    let mut all_latencies = Vec::new();
    let mut ops_completed = 0_usize;
    let mut allocations = 0_usize;
    let mut frees = 0_usize;
    let mut corruption_events = 0_usize;
    let mut max_hold_ns = 0_u64;
    for join in joins {
        let stats = join
            .join()
            .expect("priority-inversion worker must not panic");
        all_latencies.extend(stats.sampled_latencies_ns);
        ops_completed += stats.ops_completed;
        allocations += stats.allocations;
        frees += stats.frees;
        corruption_events += stats.corruption_events;
        max_hold_ns = max_hold_ns.max(stats.max_hold_ns);
    }

    let completion_time_ms = started.elapsed().as_millis() as u64;
    let baseline_p99 = baseline_p99_ns((iterations / 2).max(256), workers);
    let p99_latency_ns = percentile_ns(&mut all_latencies, 99);
    let p99_ratio_x1000 =
        ((p99_latency_ns.max(1) as u128 * 1000) / baseline_p99.max(1) as u128) as u64;

    StormReport {
        storm_type: StormType::PriorityInversion.as_str(),
        thread_count: workers,
        iterations_per_thread: iterations,
        completion_time_ms,
        deadlock_detected: monitor.deadlock_detected,
        corruption_detected: corruption_events > 0,
        ops_completed,
        allocations,
        frees,
        p99_latency_ns,
        baseline_p99_ns: baseline_p99,
        p99_ratio_x1000,
        max_hold_ns,
        max_progress_gap_ms: monitor.max_progress_gap_ms,
        signals_observed: 0,
        rr_threads_applied: rr_applied.load(Ordering::Relaxed),
        affinity_threads_applied: 0,
    }
}

fn run_storm(storm: StormType, pipeline: Arc<ValidationPipeline>) -> StormReport {
    let workers = if matches!(storm, StormType::PriorityInversion) {
        (thread_count() / 2).max(32)
    } else {
        thread_count()
    };
    let iterations = iterations_per_thread();
    match storm {
        StormType::PriorityInversion => run_priority_inversion_storm(pipeline, iterations, workers),
        _ => run_generic_storm(storm, pipeline, iterations, workers),
    }
}

fn log_row(report: &StormReport, mode: &str, seq: usize, artifact_refs: &[String]) -> Value {
    json!({
        "timestamp": format!("2026-03-31T00:00:{:02}Z", seq % 60),
        "bead_id": "bd-18qq.3",
        "trace_id": format!("bd-18qq.3::{mode}::{:03}", seq),
        "level": if report.deadlock_detected || report.corruption_detected { "error" } else { "info" },
        "event": "preemption_storm",
        "mode": mode,
        "api_family": "malloc",
        "symbol": "membrane::allocator_roundtrip",
        "decision_path": "preemption_storm->allocator_roundtrip",
        "healing_action": "None",
        "errno": 0,
        "latency_ns": report.p99_latency_ns,
        "artifact_refs": artifact_refs,
        "details": {
            "storm_type": report.storm_type,
            "thread_count": report.thread_count,
            "iterations_per_thread": report.iterations_per_thread,
            "completion_time_ms": report.completion_time_ms,
            "deadlock_detected": report.deadlock_detected,
            "corruption_detected": report.corruption_detected,
            "ops_completed": report.ops_completed,
            "allocations": report.allocations,
            "frees": report.frees,
            "p99_ratio_x1000": report.p99_ratio_x1000,
            "max_hold_ns": report.max_hold_ns,
            "max_progress_gap_ms": report.max_progress_gap_ms,
            "signals_observed": report.signals_observed,
            "rr_threads_applied": report.rr_threads_applied,
            "affinity_threads_applied": report.affinity_threads_applied
        }
    })
}

#[test]
fn preemption_storms_suite_emits_metrics() {
    let mode = current_mode_name();
    assert!(
        matches!(mode, "strict" | "hardened"),
        "preemption storms require strict/hardened mode (got {mode})"
    );

    SIGUSR1_COUNT.store(0, Ordering::Relaxed);
    let pipeline = Arc::new(ValidationPipeline::new());
    let reports: Vec<StormReport> = StormType::all()
        .into_iter()
        .map(|storm| run_storm(storm, Arc::clone(&pipeline)))
        .collect();

    for report in &reports {
        assert!(
            !report.deadlock_detected,
            "storm {} deadlocked",
            report.storm_type
        );
        assert!(
            !report.corruption_detected,
            "storm {} observed corruption",
            report.storm_type
        );
        assert_eq!(
            report.allocations, report.frees,
            "storm {} leaked operations",
            report.storm_type
        );
        assert!(
            report.max_progress_gap_ms <= STALL_BUDGET_MS,
            "storm {} stalled for {}ms",
            report.storm_type,
            report.max_progress_gap_ms
        );
        assert!(
            report.p99_ratio_x1000 < 10_000,
            "storm {} exceeded p99 slowdown budget: {}",
            report.storm_type,
            report.p99_ratio_x1000
        );
    }

    let (report_path, trace_path) = storm_artifact_paths(mode);
    let artifact_refs = vec![
        report_path.to_string_lossy().into_owned(),
        trace_path.to_string_lossy().into_owned(),
    ];
    let trace_rows: Vec<Value> = reports
        .iter()
        .enumerate()
        .map(|(idx, report)| log_row(report, mode, idx + 1, &artifact_refs))
        .collect();
    let payload = json!({
        "schema_version": "v1",
        "bead": "bd-18qq.3",
        "mode": mode,
        "artifact_refs": artifact_refs,
        "storm_results": reports.iter().map(|report| json!({
            "storm_type": report.storm_type,
            "thread_count": report.thread_count,
            "iterations_per_thread": report.iterations_per_thread,
            "completion_time_ms": report.completion_time_ms,
            "deadlock_detected": report.deadlock_detected,
            "corruption_detected": report.corruption_detected,
            "ops_completed": report.ops_completed,
            "allocations": report.allocations,
            "frees": report.frees,
            "p99_latency_ns": report.p99_latency_ns,
            "baseline_p99_ns": report.baseline_p99_ns,
            "p99_ratio_x1000": report.p99_ratio_x1000,
            "max_hold_ns": report.max_hold_ns,
            "max_progress_gap_ms": report.max_progress_gap_ms,
            "signals_observed": report.signals_observed,
            "rr_threads_applied": report.rr_threads_applied,
            "affinity_threads_applied": report.affinity_threads_applied,
        })).collect::<Vec<_>>()
    });
    write_json_artifact(&report_path, &payload);
    write_jsonl_artifact(&trace_path, &trace_rows);

    println!("PREEMPTION_STORM_REPORT {}", payload);
}
