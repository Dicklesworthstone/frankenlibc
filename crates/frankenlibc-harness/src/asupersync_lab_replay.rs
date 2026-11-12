//! Narrow asupersync Lab-backed replay prototype (bd-juvqm.15).
//!
//! Captures a single workload-trace replay against the asupersync
//! Lab tooling. The prototype is intentionally narrow — one trace
//! class — and reports tool failures separately from code failures
//! so a missing or broken `/dp/asupersync` install never masquerades
//! as a regression in frankenlibc itself.
//!
//! Captured fields per replay record:
//!   * virtual_time_seed (u64)
//!   * schedule_decisions (ordered list of String tags)
//!   * replay_inputs (artifact_ref list)
//!   * expected_outputs (artifact_ref list)
//!   * artifact_refs (everything-cited list)
//!   * source_commit (40-char SHA pinning the trace)
//!
//! Result classification — three terminal outcomes, mutually
//! exclusive:
//!   * `ReplayOutcome::Pass` — observed outputs match expected.
//!   * `ReplayOutcome::CodeFailure` — observed outputs deviate from
//!     expected. Real bug, fail closed on the workload.
//!   * `ReplayOutcome::ToolFailure { reason }` — asupersync was
//!     unavailable or returned a non-deterministic schedule. The
//!     gate reports this separately so the run is not blamed on
//!     frankenlibc code.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub schema_version: String,
    pub trace_class: String,
    pub virtual_time_seed: u64,
    pub schedule_decisions: Vec<String>,
    pub replay_inputs: Vec<String>,
    pub expected_outputs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub source_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    Pass,
    CodeFailure { signature: String },
    ToolFailure { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayValidationError {
    MissingSchemaVersion,
    MissingTraceClass,
    MissingScheduleDecisions,
    MissingReplayInputs,
    MissingExpectedOutputs,
    MissingArtifactRefs,
    StaleOrInvalidSourceCommit,
}

impl core::fmt::Display for ReplayValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReplayValidationError::MissingSchemaVersion => f.write_str("missing schema_version"),
            ReplayValidationError::MissingTraceClass => f.write_str("missing trace_class"),
            ReplayValidationError::MissingScheduleDecisions => {
                f.write_str("missing schedule_decisions")
            }
            ReplayValidationError::MissingReplayInputs => f.write_str("missing replay_inputs"),
            ReplayValidationError::MissingExpectedOutputs => {
                f.write_str("missing expected_outputs")
            }
            ReplayValidationError::MissingArtifactRefs => f.write_str("missing artifact_refs"),
            ReplayValidationError::StaleOrInvalidSourceCommit => {
                f.write_str("stale or invalid source_commit")
            }
        }
    }
}

impl std::error::Error for ReplayValidationError {}

fn missing_or_blank_entries(values: &[String]) -> bool {
    values.is_empty() || values.iter().any(|value| value.trim().is_empty())
}

/// Validate a replay record. Fails closed when ANY required field
/// is missing or blank.
pub fn validate_replay(r: &ReplayRecord) -> Result<(), ReplayValidationError> {
    if r.schema_version.trim().is_empty() {
        return Err(ReplayValidationError::MissingSchemaVersion);
    }
    if r.trace_class.trim().is_empty() {
        return Err(ReplayValidationError::MissingTraceClass);
    }
    if missing_or_blank_entries(&r.schedule_decisions) {
        return Err(ReplayValidationError::MissingScheduleDecisions);
    }
    if missing_or_blank_entries(&r.replay_inputs) {
        return Err(ReplayValidationError::MissingReplayInputs);
    }
    if missing_or_blank_entries(&r.expected_outputs) {
        return Err(ReplayValidationError::MissingExpectedOutputs);
    }
    if missing_or_blank_entries(&r.artifact_refs) {
        return Err(ReplayValidationError::MissingArtifactRefs);
    }
    let sc = &r.source_commit;
    let is_sha = sc.len() == 40 && sc.chars().all(|c| c.is_ascii_hexdigit());
    if !is_sha {
        return Err(ReplayValidationError::StaleOrInvalidSourceCommit);
    }
    // The artifact_refs union must cover every input + expected output.
    let union: BTreeSet<&str> = r.artifact_refs.iter().map(String::as_str).collect();
    for x in r.replay_inputs.iter().chain(r.expected_outputs.iter()) {
        if !union.contains(x.as_str()) {
            return Err(ReplayValidationError::MissingArtifactRefs);
        }
    }
    Ok(())
}

/// Asupersync Lab availability probe (bd-qfbhc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabAvailability {
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<std::path::PathBuf>,
    /// Stable enum-string for the detection branch that fired.
    pub detection_reason: String,
}

/// Inputs to [`detect_asupersync_available`]. Pure data, so tests
/// can craft alternate environments without mutating process env.
#[derive(Debug, Clone)]
pub struct DetectionEnv {
    /// Value of `FRANKENLIBC_ASUPERSYNC_AVAILABLE`, if present.
    pub override_var: Option<String>,
    /// Directory that, if it exists, indicates a local asupersync
    /// install (typically `/dp/asupersync`).
    pub asupersync_dir: std::path::PathBuf,
    /// Colon-split `PATH` entries to scan for an `asupersync` binary.
    pub path_search_paths: Vec<std::path::PathBuf>,
}

impl DetectionEnv {
    /// Build a [`DetectionEnv`] from real process environment +
    /// canonical `/dp/asupersync` directory.
    pub fn from_process_env() -> Self {
        let path_search_paths = std::env::var("PATH")
            .ok()
            .map(|p| {
                p.split(':')
                    .filter(|s| !s.is_empty())
                    .map(std::path::PathBuf::from)
                    .collect()
            })
            .unwrap_or_default();
        Self {
            override_var: std::env::var("FRANKENLIBC_ASUPERSYNC_AVAILABLE").ok(),
            asupersync_dir: std::path::PathBuf::from("/dp/asupersync"),
            path_search_paths,
        }
    }
}

/// Detect asupersync Lab availability with a deterministic probe
/// order:
///   1. `FRANKENLIBC_ASUPERSYNC_AVAILABLE` env override (highest
///      priority — short-circuits filesystem state).
///   2. `asupersync_dir` directory exists.
///   3. `asupersync` binary on `path_search_paths`.
///   4. Fall back to `available=false` with reason
///      `"no_install_detected"`.
///
/// `detection_reason` enum-strings:
///   * `"env_override_disabled"` — override said NO.
///   * `"env_override_enabled"` — override said YES.
///   * `"asupersync_dir_present"` — `/dp/asupersync` (or override) exists.
///   * `"binary_on_path"` — `asupersync` binary found on PATH.
///   * `"no_install_detected"` — none of the above.
pub fn detect_asupersync_available(env: &DetectionEnv) -> LabAvailability {
    if let Some(v) = &env.override_var {
        match v.trim() {
            "0" | "false" | "no" | "off" | "" => {
                return LabAvailability {
                    available: false,
                    version: None,
                    path: None,
                    detection_reason: "env_override_disabled".to_string(),
                };
            }
            "1" | "true" | "yes" | "on" => {
                return LabAvailability {
                    available: true,
                    version: None,
                    path: None,
                    detection_reason: "env_override_enabled".to_string(),
                };
            }
            _ => {}
        }
    }
    if env.asupersync_dir.is_dir() {
        return LabAvailability {
            available: true,
            version: None,
            path: Some(env.asupersync_dir.clone()),
            detection_reason: "asupersync_dir_present".to_string(),
        };
    }
    for dir in &env.path_search_paths {
        let candidate = dir.join("asupersync");
        if candidate.is_file() {
            return LabAvailability {
                available: true,
                version: None,
                path: Some(candidate),
                detection_reason: "binary_on_path".to_string(),
            };
        }
    }
    LabAvailability {
        available: false,
        version: None,
        path: None,
        detection_reason: "no_install_detected".to_string(),
    }
}

/// Stable list of every possible `detection_reason` string. Used by
/// the conformance gate to lock the contract — adding a new branch
/// requires updating this constant atomically with the manifest.
pub const DETECTION_REASONS: &[&str] = &[
    "env_override_disabled",
    "env_override_enabled",
    "asupersync_dir_present",
    "binary_on_path",
    "no_install_detected",
];

/// Synthesize a replay outcome given:
///   * the validated record
///   * whether asupersync Lab tooling reports as available
///   * the (deterministic) observed outputs
///
/// The classification is fail-closed: missing tool → `ToolFailure`
/// (NOT CodeFailure), output divergence → `CodeFailure`.
pub fn classify_outcome(
    record: &ReplayRecord,
    asupersync_available: bool,
    observed_outputs: &[String],
) -> ReplayOutcome {
    if !asupersync_available {
        return ReplayOutcome::ToolFailure {
            reason: format!(
                "asupersync tool unavailable (trace_class={}); cannot validate virtual-time replay",
                record.trace_class
            ),
        };
    }
    if observed_outputs == record.expected_outputs.as_slice() {
        ReplayOutcome::Pass
    } else {
        let missing: Vec<&str> = record
            .expected_outputs
            .iter()
            .filter(|e| !observed_outputs.contains(e))
            .map(String::as_str)
            .collect();
        let extra: Vec<&str> = observed_outputs
            .iter()
            .filter(|o| !record.expected_outputs.contains(o))
            .map(String::as_str)
            .collect();
        ReplayOutcome::CodeFailure {
            signature: format!(
                "{}::missing={};extra={}",
                record.trace_class,
                missing.join(","),
                extra.join(",")
            ),
        }
    }
}

/// Mode controlling how `execute_seeded_lab_replay` resolves companion Lab tooling.
#[derive(Debug, Clone)]
pub enum LabToolingMode {
    /// Use the compiled-in `asupersync-conformance` companion crate directly unless
    /// an explicit `DetectionEnv` override disables it.
    LinkedCrate { override_var: Option<String> },
    /// Require external environment detection (`detect_asupersync_available`).
    ExternalProbe(DetectionEnv),
    /// Explicitly simulate unavailable Lab tooling for negative-control testing.
    SimulatedUnavailable { detail: String },
}

/// Atomic concurrent step scheduled across worker queues during deterministic Lab replay.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LabTaskOp {
    /// Pin the worker's `EbrHandle` in `frankenlibc_membrane::ebr::EbrCollector`.
    PinEpoch,
    /// Drop the worker's active `EbrGuard` if currently pinned.
    UnpinEpoch,
    /// Allocate/publish logical item `item_id` into shared state.
    PublishItem { item_id: u64 },
    /// Read logical item `item_id` while verifying it has not been reclaimed by EBR.
    AccessItem { item_id: u64 },
    /// Retire logical item `item_id` into `EbrCollector::retire` so its reclamation
    /// callback marks `item_id` reclaimed only once a full 3-epoch grace period completes.
    RetireItem { item_id: u64 },
    /// Attempt `EbrCollector::try_advance()` on the collector.
    TryAdvanceEpoch,
}

/// Result of executing a real seeded Lab schedule replay via `asupersync-conformance`.
#[cfg(feature = "asupersync-tooling")]
#[derive(Debug, Clone)]
pub struct LabScheduleExecution {
    pub virtual_time_seed: u64,
    pub virtual_clock_ticks: u64,
    pub schedule_trace: Vec<String>,
    pub final_epoch: u64,
    pub total_retired: u64,
    pub total_reclaimed: u64,
    pub outcome: ReplayOutcome,
    pub shrunk_witness_jsonl: Option<String>,
    pub suite: asupersync_conformance::SuiteResult,
}

#[cfg(feature = "asupersync-tooling")]
#[inline]
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(feature = "asupersync-tooling")]
#[derive(Debug, Clone)]
struct RawInterleavingRun {
    schedule_trace: Vec<String>,
    ordered_steps: Vec<(usize, LabTaskOp)>,
    virtual_clock_ticks: u64,
    final_epoch: u64,
    total_retired: u64,
    total_reclaimed: u64,
    violation: Option<String>,
}

#[cfg(feature = "asupersync-tooling")]
fn run_concrete_ebr_steps(
    ordered_steps: &[(usize, LabTaskOp)],
    worker_count: usize,
) -> RawInterleavingRun {
    use frankenlibc_membrane::ebr::{EbrCollector, EbrGuard, EbrHandle};
    use std::sync::{Arc, Mutex};

    let collector = EbrCollector::new();
    let handles: Vec<EbrHandle<'_>> = (0..worker_count).map(|_| collector.register()).collect();
    let mut guards: Vec<Option<EbrGuard<'_>>> = (0..worker_count).map(|_| None).collect();

    let published: Arc<Mutex<BTreeSet<u64>>> = Arc::new(Mutex::new(BTreeSet::new()));
    let reclaimed: Arc<Mutex<BTreeSet<u64>>> = Arc::new(Mutex::new(BTreeSet::new()));

    let mut schedule_trace = Vec::with_capacity(ordered_steps.len());
    let mut executed_steps = Vec::with_capacity(ordered_steps.len());
    let mut virtual_clock_ticks = 0u64;
    let mut violation: Option<String> = None;

    for &(worker, ref op) in ordered_steps {
        virtual_clock_ticks = virtual_clock_ticks.saturating_add(1);
        executed_steps.push((worker, op.clone()));
        if worker >= worker_count {
            violation = Some(format!(
                "ebr_invalid_worker_index(worker=W{worker},worker_count={worker_count},vt={virtual_clock_ticks})"
            ));
            break;
        }
        match op {
            LabTaskOp::PinEpoch => {
                if guards[worker].is_none() {
                    guards[worker] = Some(handles[worker].pin());
                }
                schedule_trace.push(format!("vt={virtual_clock_ticks}:W{worker}:pin"));
            }
            LabTaskOp::UnpinEpoch => {
                guards[worker] = None;
                schedule_trace.push(format!("vt={virtual_clock_ticks}:W{worker}:unpin"));
            }
            LabTaskOp::PublishItem { item_id } => {
                published.lock().expect("published lock").insert(*item_id);
                schedule_trace.push(format!(
                    "vt={virtual_clock_ticks}:W{worker}:publish({item_id})"
                ));
            }
            LabTaskOp::AccessItem { item_id } => {
                let is_reclaimed = reclaimed.lock().expect("reclaimed lock").contains(item_id);
                let is_published = published.lock().expect("published lock").contains(item_id);
                let pinned = guards[worker].is_some();
                schedule_trace.push(format!(
                    "vt={virtual_clock_ticks}:W{worker}:access({item_id},pinned={pinned})"
                ));
                if !is_published {
                    violation = Some(format!(
                        "ebr_access_unpublished(worker=W{worker},item={item_id},vt={virtual_clock_ticks})"
                    ));
                    break;
                }
                if is_reclaimed {
                    violation = Some(format!(
                        "ebr_use_after_reclaim(worker=W{worker},item={item_id},pinned={pinned},vt={virtual_clock_ticks})"
                    ));
                    break;
                }
            }
            LabTaskOp::RetireItem { item_id } => {
                let reclaimed_ref = Arc::clone(&reclaimed);
                let id = *item_id;
                collector.retire(move || {
                    reclaimed_ref
                        .lock()
                        .expect("reclaimed callback lock")
                        .insert(id);
                });
                schedule_trace.push(format!(
                    "vt={virtual_clock_ticks}:W{worker}:retire({item_id})"
                ));
            }
            LabTaskOp::TryAdvanceEpoch => {
                let adv = collector.try_advance();
                schedule_trace.push(format!(
                    "vt={virtual_clock_ticks}:W{worker}:try_advance->{adv:?}"
                ));
            }
        }
    }

    drop(guards);
    drop(handles);
    let diag = collector.diagnostics();
    RawInterleavingRun {
        schedule_trace,
        ordered_steps: executed_steps,
        virtual_clock_ticks,
        final_epoch: diag.global_epoch,
        total_retired: diag.total_retired,
        total_reclaimed: diag.total_reclaimed,
        violation,
    }
}

#[cfg(feature = "asupersync-tooling")]
fn violation_signature_key(violation: &str) -> &str {
    violation
        .split_once(",vt=")
        .map_or(violation, |(prefix, _)| prefix)
}

#[cfg(feature = "asupersync-tooling")]
fn shrink_failing_steps(
    failing_steps: &[(usize, LabTaskOp)],
    worker_count: usize,
    expected_violation: &str,
) -> Vec<(usize, LabTaskOp)> {
    let target_key = violation_signature_key(expected_violation);
    let mut current = failing_steps.to_vec();
    let mut idx = 0usize;
    while idx < current.len() {
        let mut candidate = current.clone();
        candidate.remove(idx);
        let preserves_violation = !candidate.is_empty()
            && run_concrete_ebr_steps(&candidate, worker_count)
                .violation
                .as_deref()
                .is_some_and(|v| violation_signature_key(v) == target_key);
        if preserves_violation {
            current = candidate;
        } else {
            idx += 1;
        }
    }
    current
}

/// Execute a deterministic seeded Lab schedule replay across `worker_queues` using
/// `asupersync-conformance` structured logging, checkpoints, and witness shrinking.
#[cfg(feature = "asupersync-tooling")]
pub fn execute_seeded_lab_replay(
    record: &ReplayRecord,
    tooling_mode: &LabToolingMode,
    worker_queues: &[Vec<LabTaskOp>],
) -> Result<LabScheduleExecution, ReplayValidationError> {
    use asupersync_conformance::logging::{ConformanceTestLogger, with_test_logger};
    use asupersync_conformance::{
        Checkpoint, SuiteResult, SuiteTestResult, TestCategory, TestResult,
    };
    use serde_json::json;

    validate_replay(record)?;

    let tool_unavailable_reason: Option<String> = match tooling_mode {
        LabToolingMode::LinkedCrate { override_var } => {
            match override_var.as_deref().map(str::trim) {
                Some("0" | "false" | "no" | "off" | "") => Some(format!(
                    "asupersync tool unavailable (trace_class={}; reason=env_override_disabled); cannot validate virtual-time replay",
                    record.trace_class
                )),
                _ => None,
            }
        }
        LabToolingMode::ExternalProbe(env) => {
            let probe = detect_asupersync_available(env);
            if probe.available {
                None
            } else {
                Some(format!(
                    "asupersync tool unavailable (trace_class={}; reason={}); cannot validate virtual-time replay",
                    record.trace_class, probe.detection_reason
                ))
            }
        }
        LabToolingMode::SimulatedUnavailable { detail } => Some(format!(
            "asupersync tool unavailable (trace_class={}; reason={detail}); cannot validate virtual-time replay",
            record.trace_class
        )),
    };

    let mut suite = SuiteResult::new(format!("asupersync-lab:{}", record.trace_class));
    if let Some(reason) = tool_unavailable_reason {
        suite.results.push(SuiteTestResult {
            test_id: format!(
                "{}::seed={:#x}",
                record.trace_class, record.virtual_time_seed
            ),
            test_name: record.trace_class.clone(),
            category: TestCategory::Sync,
            expected: "asupersync Lab replay tooling available and operational".to_string(),
            result: TestResult::failed(reason.clone()),
            events: Vec::new(),
        });
        suite.total = 1;
        suite.failed = 1;
        return Ok(LabScheduleExecution {
            virtual_time_seed: record.virtual_time_seed,
            virtual_clock_ticks: 0,
            schedule_trace: Vec::new(),
            final_epoch: 0,
            total_retired: 0,
            total_reclaimed: 0,
            outcome: ReplayOutcome::ToolFailure { reason },
            shrunk_witness_jsonl: None,
            suite,
        });
    }

    let worker_count = worker_queues.len().max(1);
    let mut cursors = vec![0usize; worker_queues.len()];
    let mut rng_state = record.virtual_time_seed ^ 0xA55A_5EED_CAFE_BABEu64;
    let mut scheduled_steps: Vec<(usize, LabTaskOp)> = Vec::new();

    loop {
        let runnable: Vec<usize> = cursors
            .iter()
            .enumerate()
            .filter_map(|(w, &idx)| (idx < worker_queues[w].len()).then_some(w))
            .collect();
        if runnable.is_empty() {
            break;
        }
        let pick_idx = (splitmix64_next(&mut rng_state) as usize) % runnable.len();
        let chosen_worker = runnable[pick_idx];
        let step_idx = cursors[chosen_worker];
        cursors[chosen_worker] += 1;
        scheduled_steps.push((
            chosen_worker,
            worker_queues[chosen_worker][step_idx].clone(),
        ));
    }

    let logger = ConformanceTestLogger::new(&record.trace_class, "TSM::EBR::LabReplay");
    logger.phase("seeded_lab_schedule");

    let run = with_test_logger(&logger, || {
        asupersync_conformance::checkpoint(
            "lab.seed",
            json!({
                "trace_class": &record.trace_class,
                "virtual_time_seed": record.virtual_time_seed,
                "source_commit": &record.source_commit,
                "worker_count": worker_queues.len(),
                "total_ops": scheduled_steps.len(),
            }),
        );
        let res = run_concrete_ebr_steps(&scheduled_steps, worker_count);
        asupersync_conformance::checkpoint(
            "lab.summary",
            json!({
                "virtual_clock_ticks": res.virtual_clock_ticks,
                "final_epoch": res.final_epoch,
                "total_retired": res.total_retired,
                "total_reclaimed": res.total_reclaimed,
                "violation": &res.violation,
            }),
        );
        res
    });

    let checkpoints = vec![
        Checkpoint::new(
            "lab.seed",
            json!({
                "virtual_time_seed": record.virtual_time_seed,
                "scheduled_ops": scheduled_steps.len(),
            }),
        ),
        Checkpoint::new(
            "lab.ebr_state",
            json!({
                "final_epoch": run.final_epoch,
                "total_retired": run.total_retired,
                "total_reclaimed": run.total_reclaimed,
                "schedule_len": run.schedule_trace.len(),
            }),
        ),
    ];

    let (outcome, shrunk_witness_jsonl, mut test_result) =
        if let Some(ref violation) = run.violation {
            let shrunk = shrink_failing_steps(&run.ordered_steps, worker_count, violation);
            let mut witness_lines = Vec::with_capacity(shrunk.len() + 1);
            witness_lines.push(
                json!({
                    "schema_version": "frankenlibc.lab_witness.v1",
                    "event": "witness_header",
                    "trace_class": &record.trace_class,
                    "virtual_time_seed": record.virtual_time_seed,
                    "original_steps": run.ordered_steps.len(),
                    "shrunk_steps": shrunk.len(),
                    "violation": violation,
                })
                .to_string(),
            );
            for (step_no, (worker, op)) in shrunk.iter().enumerate() {
                witness_lines.push(
                    json!({
                        "schema_version": "frankenlibc.lab_witness.v1",
                        "event": "witness_step",
                        "step": step_no,
                        "worker": worker,
                        "op": op,
                    })
                    .to_string(),
                );
            }
            let sig = format!(
                "{}::invariant_violation={};shrunk_steps={}",
                record.trace_class,
                violation,
                shrunk.len()
            );
            (
                ReplayOutcome::CodeFailure {
                    signature: sig.clone(),
                },
                Some(witness_lines.join("\n")),
                TestResult::failed(sig),
            )
        } else {
            (ReplayOutcome::Pass, None, TestResult::passed())
        };

    test_result.checkpoints = checkpoints;
    let passed = test_result.passed;
    suite.results.push(SuiteTestResult {
        test_id: format!(
            "{}::seed={:#x}",
            record.trace_class, record.virtual_time_seed
        ),
        test_name: record.trace_class.clone(),
        category: TestCategory::Sync,
        expected: "all EBR grace-period invariants hold across seeded interleaving".to_string(),
        result: test_result,
        events: logger.events(),
    });
    suite.total = 1;
    if passed {
        suite.passed = 1;
    } else {
        suite.failed = 1;
    }

    Ok(LabScheduleExecution {
        virtual_time_seed: record.virtual_time_seed,
        virtual_clock_ticks: run.virtual_clock_ticks,
        schedule_trace: run.schedule_trace,
        final_epoch: run.final_epoch,
        total_retired: run.total_retired,
        total_reclaimed: run.total_reclaimed,
        outcome,
        shrunk_witness_jsonl,
        suite,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> ReplayRecord {
        ReplayRecord {
            schema_version: "v1".to_string(),
            trace_class: "stdio.fread_small".to_string(),
            virtual_time_seed: 0xdeadbeef,
            schedule_decisions: vec!["W:0".into(), "R:0".into(), "W:1".into()],
            replay_inputs: vec!["target/conformance/stdio_fread_small.input.jsonl".to_string()],
            expected_outputs: vec![
                "target/conformance/stdio_fread_small.expected.jsonl".to_string(),
            ],
            artifact_refs: vec![
                "target/conformance/stdio_fread_small.input.jsonl".to_string(),
                "target/conformance/stdio_fread_small.expected.jsonl".to_string(),
                "target/conformance/stdio_fread_small.observed.jsonl".to_string(),
            ],
            source_commit: "1".repeat(40),
        }
    }

    #[test]
    fn validate_accepts_well_formed_record() {
        assert_eq!(validate_replay(&record()), Ok(()));
    }

    #[test]
    fn validate_rejects_missing_schema_version() {
        let mut r = record();
        r.schema_version.clear();
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingSchemaVersion)
        );
    }

    #[test]
    fn validate_rejects_blank_top_level_strings() {
        let mut r = record();
        r.schema_version = " \t".to_string();
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingSchemaVersion)
        );

        let mut r = record();
        r.trace_class = "\n ".to_string();
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingTraceClass)
        );
    }

    #[test]
    fn validate_rejects_missing_replay_inputs() {
        let mut r = record();
        r.replay_inputs.clear();
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingReplayInputs)
        );
    }

    #[test]
    fn validate_rejects_blank_vector_entries() {
        let mut r = record();
        r.schedule_decisions.push(" ".to_string());
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingScheduleDecisions)
        );

        let mut r = record();
        r.replay_inputs.push("\t".to_string());
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingReplayInputs)
        );

        let mut r = record();
        r.expected_outputs.push("\n".to_string());
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingExpectedOutputs)
        );

        let mut r = record();
        r.artifact_refs.push(" ".to_string());
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingArtifactRefs)
        );
    }

    #[test]
    fn validate_rejects_invalid_source_commit() {
        let mut r = record();
        r.source_commit = "not-a-sha".to_string();
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::StaleOrInvalidSourceCommit)
        );
    }

    #[test]
    fn validate_rejects_replay_input_not_in_artifact_refs() {
        let mut r = record();
        r.replay_inputs
            .push("target/conformance/stdio_fread_small.uncited.jsonl".to_string());
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingArtifactRefs)
        );
    }

    #[test]
    fn outcome_pass_when_observed_matches_expected() {
        let r = record();
        let outcome = classify_outcome(&r, true, &r.expected_outputs);
        assert_eq!(outcome, ReplayOutcome::Pass);
    }

    #[test]
    fn outcome_code_failure_when_observed_diverges_from_expected() -> Result<(), String> {
        let r = record();
        let observed = vec!["target/conformance/stdio_fread_small.divergent.jsonl".to_string()];
        let ReplayOutcome::CodeFailure { signature } = classify_outcome(&r, true, &observed) else {
            return Err("expected CodeFailure outcome".to_string());
        };
        assert!(signature.starts_with("stdio.fread_small::"));
        assert!(signature.contains("missing="));
        assert!(signature.contains("extra="));
        Ok(())
    }

    #[test]
    fn outcome_tool_failure_when_asupersync_unavailable_even_if_outputs_match() -> Result<(), String>
    {
        let r = record();
        let outcome = classify_outcome(&r, false, &r.expected_outputs);
        let ReplayOutcome::ToolFailure { reason } = outcome else {
            return Err("expected ToolFailure outcome".to_string());
        };
        assert!(reason.contains("asupersync tool unavailable"));
        assert!(reason.contains("stdio.fread_small"));
        Ok(())
    }

    #[test]
    fn outcome_tool_failure_is_distinct_from_code_failure() {
        let r = record();
        let observed = vec!["divergent".to_string()];
        let tool_unavail = classify_outcome(&r, false, &observed);
        let code_fail = classify_outcome(&r, true, &observed);
        assert!(matches!(tool_unavail, ReplayOutcome::ToolFailure { .. }));
        assert!(matches!(code_fail, ReplayOutcome::CodeFailure { .. }));
        assert_ne!(tool_unavail, code_fail);
    }

    #[cfg(feature = "asupersync-tooling")]
    #[test]
    fn execute_seeded_lab_replay_records_failed_suite_on_tool_unavailable() {
        let r = record();
        let exec = execute_seeded_lab_replay(
            &r,
            &LabToolingMode::SimulatedUnavailable {
                detail: "unit_test_unavailable".to_string(),
            },
            &[vec![LabTaskOp::PinEpoch, LabTaskOp::UnpinEpoch]],
        )
        .expect("replay should return structured ToolFailure");
        assert!(matches!(exec.outcome, ReplayOutcome::ToolFailure { .. }));
        assert_eq!(exec.suite.total, 1);
        assert_eq!(exec.suite.failed, 1);
        assert_eq!(exec.suite.passed, 0);
        assert_eq!(exec.suite.results.len(), 1);
        assert!(!exec.suite.results[0].result.passed);
    }

    #[cfg(feature = "asupersync-tooling")]
    #[test]
    fn concrete_ebr_steps_guard_out_of_bounds_worker_index() {
        let res = run_concrete_ebr_steps(&[(5, LabTaskOp::PinEpoch)], 2);
        let violation = res.violation.expect("out-of-bounds worker must violate");
        assert!(violation.starts_with("ebr_invalid_worker_index(worker=W5,worker_count=2,"));
    }
}
