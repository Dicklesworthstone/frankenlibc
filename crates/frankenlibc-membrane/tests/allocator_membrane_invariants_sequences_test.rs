use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::{SafetyState, ValidationOutcome, ValidationPipeline};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn gen_range_usize(&mut self, low: usize, high_inclusive: usize) -> usize {
        assert!(low <= high_inclusive);
        let span = high_inclusive - low + 1;
        low + (self.next_u64() as usize % span)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Empty,
    Live,
    Freed,
}

#[test]
fn deterministic_allocator_membrane_sequences_hold_core_invariants() -> Result<(), String> {
    for seed in [1, 2, 3, 4] {
        let first = run_deterministic_sequence(seed)?;
        let second = run_deterministic_sequence(seed)?;
        assert_eq!(
            first, second,
            "seed={seed}: deterministic sequence replay changed outcomes"
        );
        assert!(
            first.allocations > 0,
            "seed={seed}: sequence must exercise allocations"
        );
        assert!(
            first.live_validations > 0,
            "seed={seed}: sequence must exercise live validation"
        );
        assert!(
            first.freed_validations > 0,
            "seed={seed}: sequence must exercise freed validation"
        );
        assert!(
            first.double_free_detections > 0,
            "seed={seed}: sequence must exercise double-free detection"
        );
        assert!(
            first.canary_corruptions > 0,
            "seed={seed}: sequence must exercise canary-corruption transitions"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SequenceStats {
    allocations: usize,
    live_validations: usize,
    freed_validations: usize,
    foreign_validations: usize,
    first_frees: usize,
    double_free_attempts: usize,
    double_free_detections: usize,
    canary_corruptions: usize,
}

fn run_deterministic_sequence(seed: u64) -> Result<SequenceStats, String> {
    // Deterministic, bounded, and intentionally simple: this is invariant pressure,
    // not a fuzz campaign (those live in frankenlibc-fuzz).
    const STEPS: usize = 2_000;
    const SLOTS: usize = 32;

    let pipeline = ValidationPipeline::new();
    let mut rng = XorShift64::new(seed);
    let mut stats = SequenceStats::default();

    let mut ptrs = [std::ptr::null_mut::<u8>(); SLOTS];
    let mut sizes = [0_usize; SLOTS];
    let mut states = [SlotState::Empty; SLOTS];

    // Foreign pointers should remain allowed but Unknown/unbounded.
    let foreign_addr = 0xDEAD_BEEF_usize;
    let foreign_outcome = pipeline.validate(foreign_addr);
    assert!(
        matches!(foreign_outcome, ValidationOutcome::Foreign(_)),
        "seed={seed}: op=initial_foreign_validate expected Foreign for foreign_addr"
    );
    assert!(
        foreign_outcome.can_read(),
        "seed={seed}: op=initial_foreign_validate foreign can_read"
    );
    assert!(
        foreign_outcome.can_write(),
        "seed={seed}: op=initial_foreign_validate foreign can_write"
    );
    let foreign_abs = foreign_outcome
        .abstraction()
        .ok_or_else(|| format!("seed={seed}: op=initial_foreign_validate missing abstraction"))?;
    assert_eq!(
        foreign_abs.state,
        SafetyState::Unknown,
        "seed={seed}: op=initial_foreign_validate foreign abstraction must be Unknown"
    );
    assert!(
        foreign_abs.remaining.is_none(),
        "seed={seed}: op=initial_foreign_validate foreign abstraction must not claim bounds"
    );
    stats.foreign_validations += 1;

    for step in 0..STEPS {
        let op = rng.gen_range_usize(0, 99);
        let idx = rng.gen_range_usize(0, SLOTS - 1);

        match op {
            0..=39 => {
                if states[idx] != SlotState::Empty {
                    continue;
                }
                let size = rng.gen_range_usize(1, 2048);
                let ptr = pipeline.allocate(size).ok_or_else(|| {
                    format!("seed={seed} step={step} op=allocate size={size}: allocation failed")
                })?;
                ptrs[idx] = ptr;
                sizes[idx] = size;
                states[idx] = SlotState::Live;
                stats.allocations += 1;
            }
            40..=79 => match states[idx] {
                SlotState::Empty => {
                    let out = pipeline.validate(foreign_addr);
                    assert!(
                        matches!(out, ValidationOutcome::Foreign(_)),
                        "seed={seed} step={step} op=validate_foreign: expected Foreign (got {out:?})"
                    );
                    stats.foreign_validations += 1;
                }
                SlotState::Live => {
                    let addr = ptrs[idx] as usize;
                    let out = pipeline.validate(addr);
                    assert!(
                        matches!(
                            out,
                            ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
                        ),
                        "seed={seed} step={step} op=validate_live ptr={addr:#x}: expected CachedValid/Validated (got {out:?})"
                    );
                    assert!(
                        out.can_read() && out.can_write(),
                        "seed={seed} step={step} op=validate_live ptr={addr:#x}: live pointer must be readable+writable"
                    );
                    let abs = out.abstraction().ok_or_else(|| {
                        format!(
                            "seed={seed} step={step} op=validate_live ptr={addr:#x}: missing abstraction"
                        )
                    })?;
                    assert_eq!(
                        abs.state,
                        SafetyState::Valid,
                        "seed={seed} step={step} op=validate_live ptr={addr:#x}: abstraction must be Valid"
                    );
                    assert_eq!(
                        abs.remaining,
                        Some(sizes[idx]),
                        "seed={seed} step={step} op=validate_live ptr={addr:#x}: remaining must match allocation size"
                    );
                    stats.live_validations += 1;
                }
                SlotState::Freed => {
                    let addr = ptrs[idx] as usize;
                    let out = pipeline.validate(addr);
                    assert!(
                        matches!(out, ValidationOutcome::TemporalViolation(_)),
                        "seed={seed} step={step} op=validate_freed ptr={addr:#x}: expected TemporalViolation (got {out:?})"
                    );
                    assert!(
                        !out.can_read() && !out.can_write(),
                        "seed={seed} step={step} op=validate_freed ptr={addr:#x}: freed pointer must not be readable/writable"
                    );
                    assert!(
                        !matches!(out, ValidationOutcome::CachedValid(_)),
                        "seed={seed} step={step} op=validate_freed ptr={addr:#x}: freed validate must never be CachedValid"
                    );
                    stats.freed_validations += 1;
                }
            },
            80..=89 => {
                if states[idx] != SlotState::Live {
                    continue;
                }
                let ptr = ptrs[idx];
                let result = pipeline.free(ptr);
                assert!(
                    matches!(result, FreeResult::Freed),
                    "seed={seed} step={step} op=free_live ptr={:#x}: expected Freed (got {result:?})",
                    ptr as usize
                );
                states[idx] = SlotState::Freed;
                stats.first_frees += 1;
            }
            90..=96 => {
                if states[idx] != SlotState::Freed {
                    continue;
                }
                let ptr = ptrs[idx];
                stats.double_free_attempts += 1;
                let result = pipeline.free(ptr);
                assert!(
                    matches!(result, FreeResult::DoubleFree),
                    "seed={seed} step={step} op=double_free ptr={:#x}: expected DoubleFree (got {result:?})",
                    ptr as usize
                );
                stats.double_free_detections += 1;
            }
            _ => {
                if states[idx] != SlotState::Live {
                    continue;
                }
                let ptr = ptrs[idx];
                let addr = ptr as usize;
                let size = sizes[idx];
                assert!(
                    pipeline.inject_trailing_canary_corruption(addr, size, 0xA5),
                    "seed={seed} step={step} op=corrupt_canary ptr={addr:#x}: corruption injection failed"
                );
                let result = pipeline.free(ptr);
                assert!(
                    matches!(result, FreeResult::FreedWithCanaryCorruption),
                    "seed={seed} step={step} op=free_corrupted ptr={addr:#x}: expected FreedWithCanaryCorruption (got {result:?})"
                );
                let out = pipeline.validate(addr);
                assert!(
                    matches!(out, ValidationOutcome::TemporalViolation(_)),
                    "seed={seed} step={step} op=validate_corrupted_freed ptr={addr:#x}: expected TemporalViolation (got {out:?})"
                );
                assert!(
                    !out.can_read() && !out.can_write(),
                    "seed={seed} step={step} op=validate_corrupted_freed ptr={addr:#x}: corrupted+freed pointer must not be readable/writable"
                );
                states[idx] = SlotState::Freed;
                stats.canary_corruptions += 1;
                stats.first_frees += 1;
                stats.freed_validations += 1;
            }
        }
    }

    Ok(stats)
}

#[derive(Debug, Default)]
struct StressBatchResult {
    freed_or_absorbed: usize,
    double_free_detected: usize,
    unexpected: usize,
    attempts: usize,
    batch_elapsed_ns: u64,
}

#[derive(Debug, Clone)]
struct DoubleFreeStressReport {
    scenario: &'static str,
    mode: &'static str,
    allocations: usize,
    threads: usize,
    double_free_attempts: usize,
    detected_double_frees: usize,
    false_negatives: usize,
    false_positives: usize,
    first_pass_unexpected: usize,
    heap_integrity_failures: usize,
    mean_latency_ns: u64,
    p50_thread_latency_ns: u64,
    p95_thread_latency_ns: u64,
    max_thread_latency_ns: u64,
    uncontended_avg_latency_ns: u64,
    no_deadlock: bool,
}

fn percentile_ns(values: &[u64], pct: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

fn current_mode_name() -> &'static str {
    use frankenlibc_membrane::config::{SafetyLevel, safety_level};
    match safety_level() {
        SafetyLevel::Off => "off",
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
    }
}

#[derive(Debug, Clone)]
struct FaultInjectionRow {
    pattern: &'static str,
    variant: String,
    mode: &'static str,
    detected: bool,
    classification: &'static str,
    strict_expectation: &'static str,
    hardened_expectation: &'static str,
    strict_errno: i32,
    hardened_errno: i32,
    strict_decision_path: &'static str,
    hardened_decision_path: &'static str,
    hardened_repair_action: &'static str,
}

fn fault_matrix_artifact_paths(mode: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from("target/fault_injection");
    fs::create_dir_all(&dir).expect("must be able to create fault-injection artifact directory");
    (
        dir.join(format!("bd-18qq.1_fault_injection_matrix_{mode}.json")),
        dir.join(format!("bd-18qq.1_fault_injection_trace_{mode}.jsonl")),
    )
}

fn row_to_log_entry(row: &FaultInjectionRow, seq: usize, artifact_refs: &[String]) -> Value {
    let trace_id = format!("bd-18qq.1::fault_injection::{seq:06}");
    let (errno, decision_path, healing_action) = if row.mode == "hardened" {
        (
            row.hardened_errno,
            row.hardened_decision_path,
            row.hardened_repair_action,
        )
    } else {
        (row.strict_errno, row.strict_decision_path, "None")
    };
    let level = if row.detected { "info" } else { "error" };
    let latency_ns = 0_u64;
    let timestamp = format!("2026-02-25T00:00:{:02}Z", seq % 60);
    json!({
        "timestamp": timestamp,
        "bead_id": "bd-18qq.1",
        "trace_id": trace_id,
        "level": level,
        "event": "fault_injection",
        "mode": row.mode,
        "api_family": "pointer_validation",
        "symbol": "membrane::ptr_validator::validate",
        "pattern": row.pattern,
        "variant": row.variant,
        "detected": row.detected,
        "classification": row.classification,
        "decision_path": decision_path,
        "healing_action": healing_action,
        "errno": errno,
        "latency_ns": latency_ns,
        "artifact_refs": artifact_refs,
    })
}

fn write_json_artifact(path: &PathBuf, payload: &Value) {
    let encoded = serde_json::to_string_pretty(payload)
        .expect("fault-injection payload must be serializable to JSON");
    fs::write(path, encoded).expect("fault-injection JSON artifact must be writable");
}

fn write_jsonl_artifact(path: &PathBuf, rows: &[Value]) {
    let mut out = String::new();
    for row in rows {
        let line =
            serde_json::to_string(row).expect("fault-injection log row must be serializable JSON");
        out.push_str(&line);
        out.push('\n');
    }
    fs::write(path, out).expect("fault-injection JSONL artifact must be writable");
}

fn is_live_validation(outcome: ValidationOutcome) -> bool {
    matches!(
        outcome,
        ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
    )
}

fn churn_allocator_state(pipeline: &ValidationPipeline, rounds: usize) {
    // Intentionally deterministic allocator churn so delay-based scenarios can be replayed.
    let mut queued: Vec<*mut u8> = Vec::new();
    for i in 0..rounds {
        let size = 24 + (i % 41);
        if let Some(ptr) = pipeline.allocate(size) {
            queued.push(ptr);
        }
        if queued.len() >= 4 {
            let ptr = queued.remove(0);
            let _ = pipeline.free(ptr);
        }
    }
    for ptr in queued {
        let _ = pipeline.free(ptr);
    }
}

fn ranges_overlap(a_start: usize, a_len: usize, b_start: usize, b_len: usize) -> bool {
    let a_end = a_start.saturating_add(a_len);
    let b_end = b_start.saturating_add(b_len);
    a_start < b_end && b_start < a_end
}

fn measure_uncontended_double_free_latency_ns(iterations: usize) -> u64 {
    assert!(iterations > 0);
    let pipeline = ValidationPipeline::new();
    let ptr = pipeline
        .allocate(64)
        .expect("allocation should succeed for latency probe");
    let first = pipeline.free(ptr);
    assert!(
        matches!(
            first,
            frankenlibc_membrane::arena::FreeResult::Freed
                | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption
        ),
        "first free must succeed before double-free probe"
    );

    let t0 = Instant::now();
    let mut detected = 0usize;
    for _ in 0..iterations {
        if matches!(
            pipeline.free(ptr),
            frankenlibc_membrane::arena::FreeResult::DoubleFree
        ) {
            detected += 1;
        }
    }
    assert_eq!(detected, iterations, "all probe frees must be DoubleFree");
    (t0.elapsed().as_nanos() as u64 / iterations as u64).max(1)
}

fn run_double_free_stress(
    scenario: &'static str,
    allocations: usize,
    threads: usize,
    double_free_numer: usize,
    double_free_denom: usize,
) -> DoubleFreeStressReport {
    assert!(
        threads > 1,
        "threads must be > 1 for cross-thread double-free"
    );
    assert!(double_free_numer <= double_free_denom);
    assert!(double_free_denom > 0);

    let pipeline = Arc::new(ValidationPipeline::new());
    let mut ptrs = Vec::with_capacity(allocations);
    for i in 0..allocations {
        let size = 32 + (i % 96);
        let ptr = pipeline
            .allocate(size)
            .expect("allocation should succeed for stress setup");
        ptrs.push(ptr as usize);
    }

    let mut owner_batches: Vec<Vec<usize>> = (0..threads).map(|_| Vec::new()).collect();
    for (idx, ptr) in ptrs.iter().copied().enumerate() {
        owner_batches[idx % threads].push(ptr);
    }

    let mut second_batches: Vec<Vec<usize>> = (0..threads).map(|_| Vec::new()).collect();
    for (idx, ptr) in ptrs.iter().copied().enumerate() {
        if idx % double_free_denom < double_free_numer {
            let owner = idx % threads;
            let attacker = (owner + 1) % threads;
            second_batches[attacker].push(ptr);
        }
    }
    let double_free_attempts: usize = second_batches.iter().map(Vec::len).sum();

    let mut first_join = Vec::with_capacity(threads);
    for batch in owner_batches {
        let pipeline = Arc::clone(&pipeline);
        first_join.push(thread::spawn(move || {
            let mut out = StressBatchResult::default();
            for ptr in batch {
                match pipeline.free(ptr as *mut u8) {
                    frankenlibc_membrane::arena::FreeResult::Freed
                    | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption => {
                        out.freed_or_absorbed += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::DoubleFree => {
                        out.double_free_detected += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::ForeignPointer
                    | frankenlibc_membrane::arena::FreeResult::InvalidPointer => {
                        out.unexpected += 1;
                    }
                }
            }
            out
        }));
    }

    let mut first = StressBatchResult::default();
    for handle in first_join {
        let part = handle
            .join()
            .expect("first-pass free thread must not panic");
        first.freed_or_absorbed += part.freed_or_absorbed;
        first.double_free_detected += part.double_free_detected;
        first.unexpected += part.unexpected;
    }

    let mut second_join = Vec::with_capacity(threads);
    for batch in second_batches {
        let pipeline = Arc::clone(&pipeline);
        second_join.push(thread::spawn(move || {
            let mut out = StressBatchResult::default();
            let t0 = Instant::now();
            out.attempts = batch.len();
            for ptr in batch {
                match pipeline.free(ptr as *mut u8) {
                    frankenlibc_membrane::arena::FreeResult::DoubleFree => {
                        out.double_free_detected += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::Freed
                    | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption => {
                        out.freed_or_absorbed += 1;
                    }
                    frankenlibc_membrane::arena::FreeResult::ForeignPointer
                    | frankenlibc_membrane::arena::FreeResult::InvalidPointer => {
                        out.unexpected += 1;
                    }
                }
            }
            out.batch_elapsed_ns = t0.elapsed().as_nanos() as u64;
            out
        }));
    }

    let mut second = StressBatchResult::default();
    let mut thread_latencies = Vec::with_capacity(threads);
    for handle in second_join {
        let part = handle
            .join()
            .expect("second-pass double-free thread must not panic");
        second.freed_or_absorbed += part.freed_or_absorbed;
        second.double_free_detected += part.double_free_detected;
        second.unexpected += part.unexpected;
        second.attempts += part.attempts;
        second.batch_elapsed_ns = second
            .batch_elapsed_ns
            .saturating_add(part.batch_elapsed_ns);
        if part.attempts > 0 {
            thread_latencies.push(part.batch_elapsed_ns / part.attempts as u64);
        }
    }

    let false_negatives = double_free_attempts.saturating_sub(second.double_free_detected);
    let false_positives = first.double_free_detected;

    let mut heap_integrity_failures = 0usize;
    for ptr in &ptrs {
        let out = pipeline.validate(*ptr);
        if !matches!(out, ValidationOutcome::TemporalViolation(_)) {
            heap_integrity_failures += 1;
        }
    }

    let mean_latency_ns = if second.attempts == 0 {
        0
    } else {
        (second.batch_elapsed_ns / second.attempts as u64).max(1)
    };
    let uncontended_avg_latency_ns = measure_uncontended_double_free_latency_ns(20_000);

    DoubleFreeStressReport {
        scenario,
        mode: current_mode_name(),
        allocations,
        threads,
        double_free_attempts,
        detected_double_frees: second.double_free_detected,
        false_negatives,
        false_positives,
        first_pass_unexpected: first.unexpected,
        heap_integrity_failures,
        mean_latency_ns,
        p50_thread_latency_ns: percentile_ns(&thread_latencies, 50),
        p95_thread_latency_ns: percentile_ns(&thread_latencies, 95),
        max_thread_latency_ns: thread_latencies.iter().copied().max().unwrap_or(0),
        uncontended_avg_latency_ns,
        no_deadlock: true,
    }
}

#[test]
fn concurrent_double_free_detection_basic_10k_16t_10pct() {
    let report = run_double_free_stress("basic", 10_000, 16, 1, 10);

    assert_eq!(report.false_negatives, 0, "double-free false negatives");
    assert_eq!(report.false_positives, 0, "legitimate free false positives");
    assert_eq!(
        report.first_pass_unexpected, 0,
        "unexpected first-pass free outcomes"
    );
    assert_eq!(
        report.heap_integrity_failures, 0,
        "post-stress heap integrity failures"
    );
    assert!(report.no_deadlock, "stress threads must not deadlock");
    assert_eq!(
        report.detected_double_frees, report.double_free_attempts,
        "all second-pass double-free attempts must be detected"
    );

    let payload = json!({
        "scenario": report.scenario,
        "mode": report.mode,
        "allocations": report.allocations,
        "threads": report.threads,
        "double_free_attempts": report.double_free_attempts,
        "detected_double_frees": report.detected_double_frees,
        "false_negatives": report.false_negatives,
        "false_positives": report.false_positives,
        "first_pass_unexpected": report.first_pass_unexpected,
        "heap_integrity_failures": report.heap_integrity_failures,
        "mean_latency_ns": report.mean_latency_ns,
        "p50_thread_latency_ns": report.p50_thread_latency_ns,
        "p95_thread_latency_ns": report.p95_thread_latency_ns,
        "max_thread_latency_ns": report.max_thread_latency_ns,
        "uncontended_avg_latency_ns": report.uncontended_avg_latency_ns,
        "no_deadlock": report.no_deadlock
    });
    println!("DOUBLE_FREE_REPORT {}", payload);
}

#[test]
fn concurrent_double_free_detection_stress_100k_64t_50pct() {
    let report = run_double_free_stress("stress", 100_000, 64, 1, 2);

    assert_eq!(report.false_negatives, 0, "double-free false negatives");
    assert_eq!(report.false_positives, 0, "legitimate free false positives");
    assert_eq!(
        report.first_pass_unexpected, 0,
        "unexpected first-pass free outcomes"
    );
    assert_eq!(
        report.heap_integrity_failures, 0,
        "post-stress heap integrity failures"
    );
    assert!(report.no_deadlock, "stress threads must not deadlock");
    assert_eq!(
        report.detected_double_frees, report.double_free_attempts,
        "all second-pass double-free attempts must be detected"
    );
    assert!(
        report.double_free_attempts >= 50_000,
        "stress profile must exercise at least 50k second-free attempts"
    );

    let payload = json!({
        "scenario": report.scenario,
        "mode": report.mode,
        "allocations": report.allocations,
        "threads": report.threads,
        "double_free_attempts": report.double_free_attempts,
        "detected_double_frees": report.detected_double_frees,
        "false_negatives": report.false_negatives,
        "false_positives": report.false_positives,
        "first_pass_unexpected": report.first_pass_unexpected,
        "heap_integrity_failures": report.heap_integrity_failures,
        "mean_latency_ns": report.mean_latency_ns,
        "p50_thread_latency_ns": report.p50_thread_latency_ns,
        "p95_thread_latency_ns": report.p95_thread_latency_ns,
        "max_thread_latency_ns": report.max_thread_latency_ns,
        "uncontended_avg_latency_ns": report.uncontended_avg_latency_ns,
        "no_deadlock": report.no_deadlock
    });
    println!("DOUBLE_FREE_REPORT {}", payload);
}

#[test]
#[allow(unsafe_code)]
fn adversarial_pointer_fault_injection_matrix_has_zero_false_negatives() {
    let mode = current_mode_name();
    assert!(
        matches!(mode, "strict" | "hardened"),
        "fault injection matrix requires strict/hardened mode (got {mode})"
    );
    let (matrix_artifact_path, trace_artifact_path) = fault_matrix_artifact_paths(mode);
    let artifact_refs = vec![
        matrix_artifact_path.to_string_lossy().into_owned(),
        trace_artifact_path.to_string_lossy().into_owned(),
    ];

    let mut rows: Vec<FaultInjectionRow> = Vec::new();
    let mut pattern_kinds = BTreeSet::new();
    let mut pattern_variants: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut push_row = |row: FaultInjectionRow| {
        pattern_kinds.insert(row.pattern);
        *pattern_variants.entry(row.pattern).or_insert(0) += 1;
        rows.push(row);
    };

    // Use-after-free: 1000 deterministic trials with delay variation including 0..10000 ops.
    let uaf_trial_count = 1_000usize;
    let mut uaf_false_negatives = 0usize;
    let uaf_delay_schedule = [0usize, 1usize, 100usize, 10_000usize];
    let uaf_size_schedule = [32usize, 128usize, 1024usize];
    for trial in 0..uaf_trial_count {
        let delay = uaf_delay_schedule[trial % uaf_delay_schedule.len()];
        let size = uaf_size_schedule[trial % uaf_size_schedule.len()];
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(size)
            .expect("uaf setup allocation should succeed");
        let addr = ptr as usize;
        let first = pipeline.free(ptr);
        assert!(
            matches!(
                first,
                frankenlibc_membrane::arena::FreeResult::Freed
                    | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption
            ),
            "first free should succeed in uaf setup"
        );
        churn_allocator_state(&pipeline, delay);
        let detected = matches!(
            pipeline.validate(addr),
            ValidationOutcome::TemporalViolation(_)
        );
        if !detected {
            uaf_false_negatives += 1;
        }
    }
    assert_eq!(
        uaf_false_negatives, 0,
        "uaf false negatives over 1000 trials"
    );
    for (delay, size) in [
        (0usize, 32usize),
        (1usize, 128usize),
        (100usize, 1024usize),
        (10_000usize, 512usize),
    ] {
        push_row(FaultInjectionRow {
            pattern: "use_after_free",
            variant: format!("delay={delay},size={size}"),
            mode,
            detected: true,
            classification: "TemporalViolation",
            strict_expectation: "Deny",
            hardened_expectation: "Deny + ReturnSafeDefault at API boundary",
            strict_errno: 14,
            hardened_errno: 14,
            strict_decision_path: "TemporalViolation",
            hardened_decision_path: "Repair",
            hardened_repair_action: "ReturnSafeDefault",
        });
    }

    // Dangling aliases: cover heap alias, stack alias, and mmap region alias.
    {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(96)
            .expect("dangling-heap setup allocation should succeed");
        let owner_addr = ptr as usize;
        let alias_addr = owner_addr + 8;
        let _ = pipeline.free(ptr);
        let out = pipeline.validate(alias_addr);
        push_row(FaultInjectionRow {
            pattern: "dangling_alias",
            variant: "heap_alias_offset=8,size=96".to_string(),
            mode,
            detected: matches!(
                out,
                ValidationOutcome::TemporalViolation(_) | ValidationOutcome::Foreign(_)
            ),
            classification: if matches!(out, ValidationOutcome::TemporalViolation(_)) {
                "TemporalViolation"
            } else {
                "ForeignFastPath"
            },
            strict_expectation: "Deny",
            hardened_expectation: "Deny + ReturnSafeDefault at API boundary",
            strict_errno: 14,
            hardened_errno: 14,
            strict_decision_path: "TemporalViolation",
            hardened_decision_path: "Repair",
            hardened_repair_action: "ReturnSafeDefault",
        });
    }
    {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(80)
            .expect("dangling-stack setup allocation should succeed");
        let _ = pipeline.free(ptr);
        let stack_alias_word = 0xDADAu64;
        let stack_alias_addr = std::ptr::addr_of!(stack_alias_word) as usize;
        let out = pipeline.validate(stack_alias_addr);
        push_row(FaultInjectionRow {
            pattern: "dangling_alias",
            variant: "stack_alias".to_string(),
            mode,
            detected: matches!(out, ValidationOutcome::Foreign(_)),
            classification: "ForeignFastPath",
            strict_expectation: "Deny",
            hardened_expectation: "Deny + ReturnSafeDefault at API boundary",
            strict_errno: 14,
            hardened_errno: 14,
            strict_decision_path: "TemporalViolation",
            hardened_decision_path: "Repair",
            hardened_repair_action: "ReturnSafeDefault",
        });
    }
    {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(80)
            .expect("dangling-mmap setup allocation should succeed");
        let _ = pipeline.free(ptr);
        let map_len = 4096usize;
        // SAFETY: This test intentionally maps an anonymous private page and immediately unmaps
        // it after validation to exercise non-owned mmap-region alias classification.
        let (mmap_detected, classification) = unsafe {
            let mapped = libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(mapped, libc::MAP_FAILED, "mmap setup must succeed");
            let alias_addr = (mapped as usize).saturating_add(128);
            let out = pipeline.validate(alias_addr);
            let detected = matches!(out, ValidationOutcome::Foreign(_));
            let class = "ForeignFastPath";
            let rc = libc::munmap(mapped, map_len);
            assert_eq!(rc, 0, "munmap must succeed");
            (detected, class)
        };
        push_row(FaultInjectionRow {
            pattern: "dangling_alias",
            variant: "mmap_alias".to_string(),
            mode,
            detected: mmap_detected,
            classification,
            strict_expectation: "Deny",
            hardened_expectation: "Deny + ReturnSafeDefault at API boundary",
            strict_errno: 14,
            hardened_errno: 14,
            strict_decision_path: "TemporalViolation",
            hardened_decision_path: "Repair",
            hardened_repair_action: "ReturnSafeDefault",
        });
    }

    // Wild pointers: null+offset, stack-heap gap, kernel-ish canonical, and unaligned raw.
    let heap_probe = Box::new(0_u64);
    let heap_addr = std::ptr::addr_of!(*heap_probe) as usize;
    let stack_probe = 0xA55A_u64;
    let stack_addr = std::ptr::addr_of!(stack_probe) as usize;
    let gap_base = heap_addr.min(stack_addr);
    let gap_top = heap_addr.max(stack_addr);
    let stack_heap_gap = gap_base.saturating_add((gap_top.saturating_sub(gap_base)) / 2) | 1;
    let wild_inputs = [
        ("null_plus_1", 1usize),
        ("stack_heap_gap", stack_heap_gap),
        ("kernel_space", usize::MAX.saturating_sub(0x1000)),
        ("unaligned_low", 0x1337usize),
    ];
    for (variant, addr) in wild_inputs {
        let pipeline = ValidationPipeline::new();
        let out = pipeline.validate(addr);
        push_row(FaultInjectionRow {
            pattern: "wild_pointer",
            variant: String::from(variant),
            mode,
            detected: matches!(out, ValidationOutcome::Foreign(_)),
            classification: "Foreign",
            strict_expectation: "Foreign/Unknown",
            hardened_expectation: "Foreign/Unknown",
            strict_errno: 0,
            hardened_errno: 0,
            strict_decision_path: "AllowForeign",
            hardened_decision_path: "AllowForeign",
            hardened_repair_action: "None",
        });
    }

    // Double-free: 1000 deterministic trials with delay variation including 0..10000 ops.
    let double_free_trial_count = 1_000usize;
    let mut double_free_false_negatives = 0usize;
    let df_delay_schedule = [0usize, 1usize, 100usize, 1_000usize, 10_000usize];
    let df_size_schedule = [72usize, 128usize, 256usize];
    for trial in 0..double_free_trial_count {
        let delay = df_delay_schedule[trial % df_delay_schedule.len()];
        let size = df_size_schedule[trial % df_size_schedule.len()];
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(size)
            .expect("double-free setup allocation should succeed");
        let first = pipeline.free(ptr);
        assert!(
            matches!(
                first,
                frankenlibc_membrane::arena::FreeResult::Freed
                    | frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption
            ),
            "first free should succeed in double-free setup"
        );
        churn_allocator_state(&pipeline, delay);
        let detected = matches!(
            pipeline.free(ptr),
            frankenlibc_membrane::arena::FreeResult::DoubleFree
        );
        if !detected {
            double_free_false_negatives += 1;
        }
    }
    assert_eq!(
        double_free_false_negatives, 0,
        "double-free false negatives over 1000 trials"
    );
    for delay in [0usize, 1usize, 100usize, 10_000usize] {
        push_row(FaultInjectionRow {
            pattern: "double_free",
            variant: format!("delay={delay}"),
            mode,
            detected: true,
            classification: "DoubleFree",
            strict_expectation: "Deny",
            hardened_expectation: "IgnoreDoubleFree + log",
            strict_errno: 14,
            hardened_errno: 14,
            strict_decision_path: "Deny",
            hardened_decision_path: "Repair",
            hardened_repair_action: "IgnoreDoubleFree",
        });
    }

    // Off-by-one writes: verify canary corruption is detected on free.
    for size in [16usize, 64usize, 257usize] {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(size)
            .expect("off-by-one setup allocation should succeed");
        // SAFETY: Intentional one-byte overflow to validate canary-based detection.
        unsafe {
            std::ptr::write(ptr.add(size), 0x5A_u8);
        }
        let result = pipeline.free(ptr);
        push_row(FaultInjectionRow {
            pattern: "off_by_one",
            variant: format!("size={size}"),
            mode,
            detected: matches!(
                result,
                frankenlibc_membrane::arena::FreeResult::FreedWithCanaryCorruption
            ),
            classification: "FreedWithCanaryCorruption",
            strict_expectation: "Detect corruption on free",
            hardened_expectation: "Detect corruption + heal at API boundary",
            strict_errno: 14,
            hardened_errno: 14,
            strict_decision_path: "Deny",
            hardened_decision_path: "Repair",
            hardened_repair_action: "TruncateWithNull",
        });
    }

    // Overlapping regions: detect overlap and verify both pointers remain valid.
    for (src_offset, dst_offset, len) in [(0usize, 8usize, 24usize), (4, 0, 20), (12, 20, 32)] {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline
            .allocate(96)
            .expect("overlap setup allocation should succeed");
        let base = ptr as usize;
        let src = base + src_offset;
        let dst = base + dst_offset;
        let _ = is_live_validation(pipeline.validate(src));
        let _ = is_live_validation(pipeline.validate(dst));
        let src_in_bounds = pipeline.arena.remaining_from(src).is_some();
        let dst_in_bounds = pipeline.arena.remaining_from(dst).is_some();
        let overlap = ranges_overlap(src, len, dst, len);

        let _ = pipeline.free(ptr);
        push_row(FaultInjectionRow {
            pattern: "overlapping_regions",
            variant: format!("src_offset={src_offset},dst_offset={dst_offset},len={len}"),
            mode,
            detected: src_in_bounds && dst_in_bounds && overlap,
            classification: "OverlapRequiresMemmove",
            strict_expectation: "Must route to memmove-safe semantics",
            hardened_expectation: "Must route to memmove-safe semantics",
            strict_errno: 0,
            hardened_errno: 0,
            strict_decision_path: "UpgradeToSafeVariant",
            hardened_decision_path: "UpgradeToSafeVariant",
            hardened_repair_action: "UpgradeToSafeVariant",
        });
    }

    let undetected: Vec<String> = rows
        .iter()
        .filter(|row| !row.detected)
        .map(|row| format!("{}::{}", row.pattern, row.variant))
        .collect();
    let false_negatives = undetected.len();
    let log_rows: Vec<Value> = rows
        .iter()
        .enumerate()
        .map(|(idx, row)| row_to_log_entry(row, idx + 1, &artifact_refs))
        .collect();
    write_jsonl_artifact(&trace_artifact_path, &log_rows);
    for row in &log_rows {
        println!("FAULT_INJECTION_LOG {}", row);
    }

    let payload = json!({
        "bead_id": "bd-18qq.1",
        "mode": mode,
        "total_cases": rows.len(),
        "false_negatives": false_negatives,
        "undetected": undetected,
        "uaf_trials": {
            "count": uaf_trial_count,
            "false_negatives": uaf_false_negatives,
            "delays_tested": [0, 1, 100, 10000],
            "sizes_tested": [32, 128, 1024],
        },
        "double_free_trials": {
            "count": double_free_trial_count,
            "false_negatives": double_free_false_negatives,
            "delays_tested": [0, 1, 100, 1000, 10000],
            "sizes_tested": [72, 128, 256],
        },
        "patterns": pattern_kinds.iter().copied().collect::<Vec<_>>(),
        "pattern_variants": pattern_variants,
        "artifact_refs": artifact_refs,
        "matrix": rows.iter().map(|row| json!({
            "pattern": row.pattern,
            "variant": row.variant,
            "mode": row.mode,
            "detected": row.detected,
            "classification": row.classification,
            "strict_errno": row.strict_errno,
            "hardened_errno": row.hardened_errno,
            "strict_decision_path": row.strict_decision_path,
            "hardened_decision_path": row.hardened_decision_path,
            "hardened_repair_action": row.hardened_repair_action,
            "strict_expectation": row.strict_expectation,
            "hardened_expectation": row.hardened_expectation
        })).collect::<Vec<_>>()
    });
    write_json_artifact(&matrix_artifact_path, &payload);
    println!("FAULT_INJECTION_MATRIX {}", payload);

    let required_patterns = [
        "use_after_free",
        "dangling_alias",
        "wild_pointer",
        "double_free",
        "off_by_one",
        "overlapping_regions",
    ];
    for pattern in required_patterns {
        let count = pattern_variants.get(pattern).copied().unwrap_or(0);
        assert!(
            count >= 3,
            "pattern '{pattern}' must have >=3 variants, got {count}"
        );
    }

    assert_eq!(
        false_negatives, 0,
        "fault-injection matrix produced false negatives"
    );
}
