//! Reusable fault-injection framework for FrankenLibC tooling.
//!
//! The goal is to let harness-driven workflows and future `frankenlab run <scenario>`
//! integrations share one declarative scenario catalog with deterministic execution,
//! structured logs, and replayable artifacts.

use crate::structured_log::{
    ArtifactIndex, ArtifactJoinKeys, LogEmitter, LogEntry, LogLevel, Outcome, StreamKind,
};
use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::{ValidationOutcome, ValidationPipeline};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

pub const FAULT_INJECTION_SCHEMA_VERSION: &str = "v1";
pub const FAULT_INJECTION_BEAD_ID: &str = "bd-3fil";
const FAULT_INJECTION_GATE: &str = "fault_injection";

#[derive(Debug, Error)]
pub enum FaultInjectionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("unknown scenario '{0}'")]
    UnknownScenario(String),
    #[error("unsupported mode '{0}'")]
    UnsupportedMode(String),
    #[error("unsupported fault scenario target='{target}' operation='{operation}'")]
    UnsupportedScenario { target: String, operation: String },
    #[error("scenario '{scenario}' variant '{variant}' missing param '{param}'")]
    MissingParam {
        scenario: String,
        variant: String,
        param: String,
    },
    #[error("scenario '{scenario}' variant '{variant}' has invalid param '{param}': {reason}")]
    InvalidParam {
        scenario: String,
        variant: String,
        param: String,
        reason: String,
    },
    #[error("scenario '{scenario}' execution failed: {reason}")]
    ExecutionFailure { scenario: String, reason: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FaultDomain {
    Memory,
    Time,
    Concurrency,
}

impl FaultDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Time => "time",
            Self::Concurrency => "concurrency",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub generated_utc: String,
    pub description: String,
    pub scenarios: Vec<FaultScenario>,
}

impl FaultManifest {
    pub fn from_path(path: &Path) -> Result<Self, FaultInjectionError> {
        let body = fs::read_to_string(path)?;
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("yaml") | Some("yml") => Self::from_yaml_str(&body),
            _ => Self::from_json_str(&body),
        }
    }

    pub fn from_yaml_str(body: &str) -> Result<Self, FaultInjectionError> {
        Ok(serde_yaml::from_str(body)?)
    }

    pub fn from_json_str(body: &str) -> Result<Self, FaultInjectionError> {
        Ok(serde_json::from_str(body)?)
    }

    #[must_use]
    pub fn scenario(&self, id: &str) -> Option<&FaultScenario> {
        self.scenarios.iter().find(|scenario| scenario.id == id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultScenario {
    pub id: String,
    pub label: String,
    pub domain: FaultDomain,
    pub target: String,
    pub operation: String,
    pub description: String,
    pub api_family: String,
    pub symbol: String,
    #[serde(default)]
    pub modes: Vec<String>,
    pub strict: FaultExpectation,
    pub hardened: FaultExpectation,
    #[serde(default)]
    pub variants: Vec<FaultVariant>,
}

impl FaultScenario {
    #[must_use]
    pub fn active_modes<'a>(&'a self, requested_modes: &'a [String]) -> Vec<&'a str> {
        let requested: BTreeSet<&str> = requested_modes.iter().map(String::as_str).collect();
        let scenario_modes: Vec<&str> = if self.modes.is_empty() {
            vec!["strict", "hardened"]
        } else {
            self.modes.iter().map(String::as_str).collect()
        };
        scenario_modes
            .into_iter()
            .filter(|mode| requested.contains(mode))
            .collect()
    }

    pub fn expectation(&self, mode: &str) -> Result<&FaultExpectation, FaultInjectionError> {
        match mode {
            "strict" => Ok(&self.strict),
            "hardened" => Ok(&self.hardened),
            other => Err(FaultInjectionError::UnsupportedMode(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultVariant {
    pub id: String,
    #[serde(default = "empty_params")]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultExpectation {
    #[serde(default = "default_expected_detection")]
    pub detected: bool,
    pub classification: String,
    pub decision_path: String,
    pub healing_action: String,
    pub errno: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FaultObservation {
    pub detected: bool,
    pub classification: String,
    pub latency_ns: u64,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultCaseReport {
    pub trace_id: String,
    pub scenario_id: String,
    pub label: String,
    pub domain: FaultDomain,
    pub target: String,
    pub operation: String,
    pub variant: String,
    pub mode: String,
    pub api_family: String,
    pub symbol: String,
    pub detected: bool,
    pub expected_detected: bool,
    pub status: String,
    pub observed_classification: String,
    pub expected_classification: String,
    pub decision_path: String,
    pub healing_action: String,
    pub errno: i32,
    pub latency_ns: u64,
    pub artifact_refs: Vec<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultRunSummary {
    pub scenario_count: usize,
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub false_negatives: usize,
    pub mismatches: usize,
    pub by_domain: BTreeMap<String, usize>,
    pub by_mode: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaultRunReport {
    pub schema_version: String,
    pub bead: String,
    pub manifest_id: String,
    pub generated_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario_filter: Option<String>,
    pub summary: FaultRunSummary,
    pub artifact_refs: Vec<String>,
    pub cases: Vec<FaultCaseReport>,
}

#[derive(Debug, Clone)]
pub struct FaultRunConfig {
    pub out_dir: PathBuf,
    pub report_path: PathBuf,
    pub log_path: PathBuf,
    pub artifact_index_path: PathBuf,
    pub bead_id: String,
    pub run_id: String,
    pub manifest_ref: Option<String>,
}

impl FaultRunConfig {
    #[must_use]
    pub fn new(out_dir: PathBuf) -> Self {
        Self {
            report_path: out_dir.join("fault_injection.current.v1.json"),
            log_path: out_dir.join("fault_injection.log.jsonl"),
            artifact_index_path: out_dir.join("fault_injection.artifacts.v1.json"),
            out_dir,
            bead_id: FAULT_INJECTION_BEAD_ID.to_string(),
            run_id: "fault-injection".to_string(),
            manifest_ref: None,
        }
    }
}

pub trait FaultExecutor {
    fn execute_case(
        &mut self,
        scenario: &FaultScenario,
        variant: &FaultVariant,
    ) -> Result<FaultObservation, FaultInjectionError>;
}

#[derive(Debug, Default)]
pub struct DefaultFaultExecutor;

impl FaultExecutor for DefaultFaultExecutor {
    fn execute_case(
        &mut self,
        scenario: &FaultScenario,
        variant: &FaultVariant,
    ) -> Result<FaultObservation, FaultInjectionError> {
        match scenario.domain {
            FaultDomain::Memory => execute_memory_case(scenario, variant),
            FaultDomain::Time => execute_time_case(scenario, variant),
            FaultDomain::Concurrency => execute_concurrency_case(scenario, variant),
        }
    }
}

pub fn run_manifest_with_default_executor(
    manifest: &FaultManifest,
    scenario_filter: Option<&str>,
    modes: &[String],
    config: &FaultRunConfig,
) -> Result<FaultRunReport, FaultInjectionError> {
    let mut executor = DefaultFaultExecutor;
    run_manifest(manifest, scenario_filter, modes, config, &mut executor)
}

pub fn run_manifest<E: FaultExecutor>(
    manifest: &FaultManifest,
    scenario_filter: Option<&str>,
    modes: &[String],
    config: &FaultRunConfig,
    executor: &mut E,
) -> Result<FaultRunReport, FaultInjectionError> {
    if modes.is_empty() {
        return Err(FaultInjectionError::UnsupportedMode(
            "at least one mode is required".to_string(),
        ));
    }

    ensure_parent_dir(&config.report_path)?;
    ensure_parent_dir(&config.log_path)?;
    ensure_parent_dir(&config.artifact_index_path)?;
    fs::create_dir_all(&config.out_dir)?;

    let selected: Vec<&FaultScenario> = match scenario_filter {
        Some(id) => vec![
            manifest
                .scenario(id)
                .ok_or_else(|| FaultInjectionError::UnknownScenario(id.to_string()))?,
        ],
        None => manifest.scenarios.iter().collect(),
    };

    let artifact_refs = run_artifact_refs(config);
    let mut emitter = LogEmitter::to_file(&config.log_path, &config.bead_id, &config.run_id)?;
    let mut summary = FaultRunSummary {
        scenario_count: selected.len(),
        ..FaultRunSummary::default()
    };
    let mut cases = Vec::new();
    let mut seq = 0_u64;

    for scenario in selected {
        let active_modes = scenario.active_modes(modes);
        if active_modes.is_empty() {
            continue;
        }

        for variant in &scenario.variants {
            let observation = executor.execute_case(scenario, variant)?;

            for mode in active_modes.iter().copied() {
                let expected = scenario.expectation(mode)?;
                let passed = observation.detected == expected.detected
                    && observation.classification == expected.classification;
                if expected.detected && !observation.detected {
                    summary.false_negatives += 1;
                }
                if !passed {
                    summary.failed += 1;
                    if observation.detected != expected.detected
                        || observation.classification != expected.classification
                    {
                        summary.mismatches += 1;
                    }
                } else {
                    summary.passed += 1;
                }
                summary.total_cases += 1;
                *summary
                    .by_domain
                    .entry(scenario.domain.as_str().to_string())
                    .or_insert(0) += 1;
                *summary.by_mode.entry(mode.to_string()).or_insert(0) += 1;

                seq += 1;
                let trace_id = deterministic_trace_id(&config.bead_id, &config.run_id, seq);
                let details = json!({
                    "target": scenario.target,
                    "operation": scenario.operation,
                    "variant_params": variant.params,
                    "expected_detected": expected.detected,
                    "expected_classification": expected.classification,
                    "observed_classification": observation.classification,
                    "observation": observation.details,
                });
                let level = if passed {
                    LogLevel::Info
                } else {
                    LogLevel::Error
                };
                let outcome = if passed { Outcome::Pass } else { Outcome::Fail };

                let entry = LogEntry::new(trace_id.clone(), level, "fault_injection")
                    .with_bead(config.bead_id.as_str())
                    .with_stream(StreamKind::Conformance)
                    .with_gate(FAULT_INJECTION_GATE)
                    .with_scenario_id(scenario.id.as_str())
                    .with_mode(mode)
                    .with_api(scenario.api_family.as_str(), scenario.symbol.as_str())
                    .with_decision_path(expected.decision_path.clone())
                    .with_healing_action(expected.healing_action.clone())
                    .with_outcome(outcome)
                    .with_errno(expected.errno)
                    .with_latency_ns(observation.latency_ns)
                    .with_artifacts(artifact_refs.clone())
                    .with_details(details.clone());
                emitter.emit_entry(entry)?;

                cases.push(FaultCaseReport {
                    trace_id,
                    scenario_id: scenario.id.clone(),
                    label: scenario.label.clone(),
                    domain: scenario.domain,
                    target: scenario.target.clone(),
                    operation: scenario.operation.clone(),
                    variant: variant.id.clone(),
                    mode: mode.to_string(),
                    api_family: scenario.api_family.clone(),
                    symbol: scenario.symbol.clone(),
                    detected: observation.detected,
                    expected_detected: expected.detected,
                    status: if passed {
                        "pass".to_string()
                    } else {
                        "fail".to_string()
                    },
                    observed_classification: observation.classification.clone(),
                    expected_classification: expected.classification.clone(),
                    decision_path: expected.decision_path.clone(),
                    healing_action: expected.healing_action.clone(),
                    errno: expected.errno,
                    latency_ns: observation.latency_ns,
                    artifact_refs: artifact_refs.clone(),
                    details,
                });
            }
        }
    }
    emitter.flush()?;

    let report = FaultRunReport {
        schema_version: FAULT_INJECTION_SCHEMA_VERSION.to_string(),
        bead: config.bead_id.clone(),
        manifest_id: manifest.manifest_id.clone(),
        generated_at_utc: now_utc(),
        scenario_filter: scenario_filter.map(str::to_string),
        summary,
        artifact_refs: artifact_refs.clone(),
        cases,
    };
    write_json_pretty(&config.report_path, &report)?;

    let join_keys = artifact_join_keys(&report);
    let mut artifact_index = ArtifactIndex::new(config.run_id.clone(), config.bead_id.clone());
    artifact_index.add_with_join_keys(
        config.log_path.to_string_lossy().into_owned(),
        "log",
        sha256_path(&config.log_path)?,
        join_keys.clone(),
    );
    artifact_index.add_with_join_keys(
        config.report_path.to_string_lossy().into_owned(),
        "report",
        sha256_path(&config.report_path)?,
        join_keys.clone(),
    );
    if let Some(manifest_ref) = &config.manifest_ref {
        let manifest_path = Path::new(manifest_ref);
        if manifest_path.exists() {
            artifact_index.add_with_join_keys(
                manifest_ref.clone(),
                "manifest",
                sha256_path(manifest_path)?,
                join_keys,
            );
        }
    }
    write_json_pretty(&config.artifact_index_path, &artifact_index)?;

    Ok(report)
}

fn execute_memory_case(
    scenario: &FaultScenario,
    variant: &FaultVariant,
) -> Result<FaultObservation, FaultInjectionError> {
    match (scenario.target.as_str(), scenario.operation.as_str()) {
        ("membrane_ptr_validator", "use_after_free") => {
            let size = param_usize(&variant.params, scenario, variant, "size")?;
            let delay = param_usize(&variant.params, scenario, variant, "delay")?;
            let pipeline = ValidationPipeline::new();
            let ptr =
                pipeline
                    .allocate(size)
                    .ok_or_else(|| FaultInjectionError::ExecutionFailure {
                        scenario: scenario.id.clone(),
                        reason: format!("failed to allocate {size} bytes"),
                    })?;
            let addr = ptr as usize;
            let result = pipeline.free(ptr);
            if !matches!(
                result,
                FreeResult::Freed | FreeResult::FreedWithCanaryCorruption
            ) {
                return Err(FaultInjectionError::ExecutionFailure {
                    scenario: scenario.id.clone(),
                    reason: format!("unexpected first free result: {result:?}"),
                });
            }

            churn_allocator_state(&pipeline, delay)?;
            let started = Instant::now();
            let outcome = pipeline.validate(addr);
            Ok(FaultObservation {
                detected: matches!(outcome, ValidationOutcome::TemporalViolation(_)),
                classification: validation_outcome_label(&outcome).to_string(),
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "size": size,
                    "delay": delay,
                    "free_result": format!("{result:?}"),
                }),
            })
        }
        ("membrane_ptr_validator", "double_free") => {
            let size = param_usize(&variant.params, scenario, variant, "size")?;
            let delay = param_usize(&variant.params, scenario, variant, "delay")?;
            let pipeline = ValidationPipeline::new();
            let ptr =
                pipeline
                    .allocate(size)
                    .ok_or_else(|| FaultInjectionError::ExecutionFailure {
                        scenario: scenario.id.clone(),
                        reason: format!("failed to allocate {size} bytes"),
                    })?;
            let first = pipeline.free(ptr);
            if !matches!(
                first,
                FreeResult::Freed | FreeResult::FreedWithCanaryCorruption
            ) {
                return Err(FaultInjectionError::ExecutionFailure {
                    scenario: scenario.id.clone(),
                    reason: format!("unexpected first free result: {first:?}"),
                });
            }

            churn_allocator_state(&pipeline, delay)?;
            let started = Instant::now();
            let second = pipeline.free(ptr);
            Ok(FaultObservation {
                detected: matches!(second, FreeResult::DoubleFree),
                classification: free_result_label(second).to_string(),
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "size": size,
                    "delay": delay,
                    "first_free": format!("{first:?}"),
                    "second_free": format!("{second:?}"),
                }),
            })
        }
        ("membrane_ptr_validator", "off_by_one") => {
            let size = param_usize(&variant.params, scenario, variant, "size")?;
            let fill_byte =
                param_u8_with_default(&variant.params, scenario, variant, "fill_byte", 0x5A)?;
            let pipeline = ValidationPipeline::new();
            let ptr =
                pipeline
                    .allocate(size)
                    .ok_or_else(|| FaultInjectionError::ExecutionFailure {
                        scenario: scenario.id.clone(),
                        reason: format!("failed to allocate {size} bytes"),
                    })?;
            if !pipeline.inject_trailing_canary_corruption(ptr as usize, size, fill_byte) {
                return Err(FaultInjectionError::ExecutionFailure {
                    scenario: scenario.id.clone(),
                    reason: "failed to inject canary corruption".to_string(),
                });
            }

            let started = Instant::now();
            let result = pipeline.free(ptr);
            Ok(FaultObservation {
                detected: matches!(result, FreeResult::FreedWithCanaryCorruption),
                classification: free_result_label(result).to_string(),
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "size": size,
                    "fill_byte": fill_byte,
                    "free_result": format!("{result:?}"),
                }),
            })
        }
        ("memory_budget", "oom") => {
            let budget_bytes = param_usize(&variant.params, scenario, variant, "budget_bytes")?;
            let reserve_bytes =
                param_usize_with_default(&variant.params, scenario, variant, "reserve_bytes", 0)?;
            let requested_bytes =
                param_usize(&variant.params, scenario, variant, "requested_bytes")?;
            let available = budget_bytes.saturating_sub(reserve_bytes);
            let started = Instant::now();
            Ok(FaultObservation {
                detected: requested_bytes > available,
                classification: if requested_bytes > available {
                    "OutOfMemoryInjected".to_string()
                } else {
                    "WithinBudget".to_string()
                },
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "budget_bytes": budget_bytes,
                    "reserve_bytes": reserve_bytes,
                    "available_bytes": available,
                    "requested_bytes": requested_bytes,
                }),
            })
        }
        _ => Err(FaultInjectionError::UnsupportedScenario {
            target: scenario.target.clone(),
            operation: scenario.operation.clone(),
        }),
    }
}

fn execute_time_case(
    scenario: &FaultScenario,
    variant: &FaultVariant,
) -> Result<FaultObservation, FaultInjectionError> {
    match (scenario.target.as_str(), scenario.operation.as_str()) {
        ("virtual_clock", "virtual_drift") => {
            let base_ns = param_u64(&variant.params, scenario, variant, "base_ns")?;
            let drift_ns = param_i64(&variant.params, scenario, variant, "drift_ns")?;
            let max_drift_ns = param_u64(&variant.params, scenario, variant, "max_drift_ns")?;
            let observed_ns = if drift_ns.is_negative() {
                base_ns.saturating_sub(drift_ns.unsigned_abs())
            } else {
                base_ns.saturating_add(drift_ns as u64)
            };
            let started = Instant::now();
            Ok(FaultObservation {
                detected: drift_ns.unsigned_abs() > max_drift_ns,
                classification: if drift_ns.unsigned_abs() > max_drift_ns {
                    "ClockDriftExceeded".to_string()
                } else {
                    "ClockStable".to_string()
                },
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "base_ns": base_ns,
                    "observed_ns": observed_ns,
                    "drift_ns": drift_ns,
                    "max_drift_ns": max_drift_ns,
                }),
            })
        }
        _ => Err(FaultInjectionError::UnsupportedScenario {
            target: scenario.target.clone(),
            operation: scenario.operation.clone(),
        }),
    }
}

fn execute_concurrency_case(
    scenario: &FaultScenario,
    variant: &FaultVariant,
) -> Result<FaultObservation, FaultInjectionError> {
    match (scenario.target.as_str(), scenario.operation.as_str()) {
        ("deterministic_scheduler", "aba_hazard") => {
            let initial_generation =
                param_u64(&variant.params, scenario, variant, "initial_generation")?;
            let recycled_generation =
                param_u64(&variant.params, scenario, variant, "recycled_generation")?;
            let started = Instant::now();
            Ok(FaultObservation {
                detected: initial_generation == recycled_generation,
                classification: if initial_generation == recycled_generation {
                    "AbaHazard".to_string()
                } else {
                    "GenerationUnique".to_string()
                },
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "initial_generation": initial_generation,
                    "recycled_generation": recycled_generation,
                }),
            })
        }
        ("deterministic_scheduler", "starvation_budget") => {
            let waiters = param_u64_with_default(&variant.params, scenario, variant, "waiters", 0)?;
            let max_skips = param_usize(&variant.params, scenario, variant, "max_skips")?;
            let grants = param_u64_array(&variant.params, scenario, variant, "grants")?;
            let longest_skip_run = longest_zero_run(&grants);
            let started = Instant::now();
            Ok(FaultObservation {
                detected: longest_skip_run > max_skips,
                classification: if longest_skip_run > max_skips {
                    "StarvationDetected".to_string()
                } else {
                    "FairProgress".to_string()
                },
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "waiters": waiters,
                    "max_skips": max_skips,
                    "longest_skip_run": longest_skip_run,
                    "grants": grants,
                }),
            })
        }
        ("deterministic_scheduler", "cancellation_window") => {
            let cancel_at = param_str(&variant.params, scenario, variant, "cancel_at")?;
            let worst_point = param_str(&variant.params, scenario, variant, "worst_point")?;
            let phase_count =
                param_u64_with_default(&variant.params, scenario, variant, "phase_count", 0)?;
            let started = Instant::now();
            Ok(FaultObservation {
                detected: cancel_at == worst_point,
                classification: if cancel_at == worst_point {
                    "CancellationAtWorstPoint".to_string()
                } else {
                    "CancellationContained".to_string()
                },
                latency_ns: started.elapsed().as_nanos() as u64,
                details: json!({
                    "cancel_at": cancel_at,
                    "worst_point": worst_point,
                    "phase_count": phase_count,
                }),
            })
        }
        _ => Err(FaultInjectionError::UnsupportedScenario {
            target: scenario.target.clone(),
            operation: scenario.operation.clone(),
        }),
    }
}

fn empty_params() -> Value {
    json!({})
}

fn default_expected_detection() -> bool {
    true
}

fn deterministic_trace_id(bead_id: &str, run_id: &str, seq: u64) -> String {
    format!("{bead_id}::{run_id}::{seq:03}")
}

fn artifact_join_keys(report: &FaultRunReport) -> ArtifactJoinKeys {
    ArtifactJoinKeys {
        trace_ids: report
            .cases
            .iter()
            .map(|case| case.trace_id.clone())
            .collect(),
        ..ArtifactJoinKeys::default()
    }
}

fn run_artifact_refs(config: &FaultRunConfig) -> Vec<String> {
    let mut refs = vec![
        config.report_path.to_string_lossy().into_owned(),
        config.log_path.to_string_lossy().into_owned(),
        config.artifact_index_path.to_string_lossy().into_owned(),
    ];
    if let Some(manifest_ref) = &config.manifest_ref {
        refs.push(manifest_ref.clone());
    }
    refs
}

fn ensure_parent_dir(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), FaultInjectionError> {
    let encoded = serde_json::to_string_pretty(value)?;
    fs::write(path, encoded)?;
    Ok(())
}

fn sha256_path(path: &Path) -> Result<String, FaultInjectionError> {
    let bytes = fs::read(path)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn now_utc() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        1970 + secs / 31_557_600,
        (secs % 31_557_600) / 2_629_800 + 1,
        (secs % 2_629_800) / 86_400 + 1,
        (secs % 86_400) / 3_600,
        (secs % 3_600) / 60,
        secs % 60,
        millis,
    )
}

fn churn_allocator_state(
    pipeline: &ValidationPipeline,
    rounds: usize,
) -> Result<(), FaultInjectionError> {
    let mut queued = Vec::new();
    for i in 0..rounds {
        let size = 24 + (i % 41);
        let ptr = pipeline
            .allocate(size)
            .ok_or_else(|| FaultInjectionError::ExecutionFailure {
                scenario: "fault_injection".to_string(),
                reason: format!("allocator churn failed at round {i}"),
            })?;
        queued.push(ptr);
        if queued.len() >= 4 {
            let ptr = queued.remove(0);
            let _ = pipeline.free(ptr);
        }
    }
    for ptr in queued {
        let _ = pipeline.free(ptr);
    }
    Ok(())
}

fn validation_outcome_label(outcome: &ValidationOutcome) -> &'static str {
    match outcome {
        ValidationOutcome::Null => "Null",
        ValidationOutcome::CachedValid(_) => "CachedValid",
        ValidationOutcome::Validated(_) => "Validated",
        ValidationOutcome::Foreign(_) => "Foreign",
        ValidationOutcome::TemporalViolation(_) => "TemporalViolation",
        ValidationOutcome::Invalid(_) => "Invalid",
        ValidationOutcome::Denied(_) => "Denied",
        ValidationOutcome::Bypassed => "Bypassed",
    }
}

fn free_result_label(result: FreeResult) -> &'static str {
    match result {
        FreeResult::Freed => "Freed",
        FreeResult::FreedWithCanaryCorruption => "FreedWithCanaryCorruption",
        FreeResult::DoubleFree => "DoubleFree",
        FreeResult::ForeignPointer => "ForeignPointer",
        FreeResult::InvalidPointer => "InvalidPointer",
    }
}

fn longest_zero_run(values: &[u64]) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for value in values {
        if *value == 0 {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

fn param_u64(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
) -> Result<u64, FaultInjectionError> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| match params.get(key) {
            Some(value) => FaultInjectionError::InvalidParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
                reason: format!("expected u64, got {value}"),
            },
            None => FaultInjectionError::MissingParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
            },
        })
}

fn param_u64_with_default(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
    default: u64,
) -> Result<u64, FaultInjectionError> {
    match params.get(key) {
        Some(_) => param_u64(params, scenario, variant, key),
        None => Ok(default),
    }
}

fn param_usize(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
) -> Result<usize, FaultInjectionError> {
    usize::try_from(param_u64(params, scenario, variant, key)?).map_err(|_| {
        FaultInjectionError::InvalidParam {
            scenario: scenario.id.clone(),
            variant: variant.id.clone(),
            param: key.to_string(),
            reason: "value does not fit usize".to_string(),
        }
    })
}

fn param_usize_with_default(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
    default: usize,
) -> Result<usize, FaultInjectionError> {
    match params.get(key) {
        Some(_) => param_usize(params, scenario, variant, key),
        None => Ok(default),
    }
}

fn param_u8_with_default(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
    default: u8,
) -> Result<u8, FaultInjectionError> {
    match params.get(key) {
        Some(_) => {
            let value = param_u64(params, scenario, variant, key)?;
            u8::try_from(value).map_err(|_| FaultInjectionError::InvalidParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
                reason: "value does not fit u8".to_string(),
            })
        }
        None => Ok(default),
    }
}

fn param_i64(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
) -> Result<i64, FaultInjectionError> {
    params
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| match params.get(key) {
            Some(value) => FaultInjectionError::InvalidParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
                reason: format!("expected i64, got {value}"),
            },
            None => FaultInjectionError::MissingParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
            },
        })
}

fn param_str(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
) -> Result<String, FaultInjectionError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| match params.get(key) {
            Some(value) => FaultInjectionError::InvalidParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
                reason: format!("expected string, got {value}"),
            },
            None => FaultInjectionError::MissingParam {
                scenario: scenario.id.clone(),
                variant: variant.id.clone(),
                param: key.to_string(),
            },
        })
}

fn param_u64_array(
    params: &Value,
    scenario: &FaultScenario,
    variant: &FaultVariant,
    key: &str,
) -> Result<Vec<u64>, FaultInjectionError> {
    let raw = params
        .get(key)
        .ok_or_else(|| FaultInjectionError::MissingParam {
            scenario: scenario.id.clone(),
            variant: variant.id.clone(),
            param: key.to_string(),
        })?;
    let array = raw
        .as_array()
        .ok_or_else(|| FaultInjectionError::InvalidParam {
            scenario: scenario.id.clone(),
            variant: variant.id.clone(),
            param: key.to_string(),
            reason: format!("expected array, got {raw}"),
        })?;
    array
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            value
                .as_u64()
                .ok_or_else(|| FaultInjectionError::InvalidParam {
                    scenario: scenario.id.clone(),
                    variant: variant.id.clone(),
                    param: format!("{key}[{idx}]"),
                    reason: format!("expected u64, got {value}"),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MANIFEST_YAML: &str = r#"
schema_version: v1
manifest_id: test-fault-manifest
generated_utc: "2026-04-06T00:00:00Z"
description: test catalog
scenarios:
  - id: memory.use_after_free
    label: use_after_free
    domain: memory
    target: membrane_ptr_validator
    operation: use_after_free
    description: exercise freed-pointer detection
    api_family: pointer_validation
    symbol: membrane::ptr_validator::validate
    strict:
      detected: true
      classification: TemporalViolation
      decision_path: TemporalViolation
      healing_action: None
      errno: 14
    hardened:
      detected: true
      classification: TemporalViolation
      decision_path: Repair
      healing_action: ReturnSafeDefault
      errno: 14
    variants:
      - id: small_delay
        params:
          size: 64
          delay: 4
  - id: time.virtual_drift
    label: virtual_drift
    domain: time
    target: virtual_clock
    operation: virtual_drift
    description: detect virtual clock drift beyond the configured budget
    api_family: time
    symbol: clock_gettime
    strict:
      detected: true
      classification: ClockDriftExceeded
      decision_path: Deny
      healing_action: None
      errno: 34
    hardened:
      detected: true
      classification: ClockDriftExceeded
      decision_path: Repair
      healing_action: ReturnSafeDefault
      errno: 34
    variants:
      - id: drifted
        params:
          base_ns: 1000000
          drift_ns: 90000
          max_drift_ns: 25000
  - id: concurrency.starvation_budget
    label: starvation_budget
    domain: concurrency
    target: deterministic_scheduler
    operation: starvation_budget
    description: detect scheduler starvation past the fairness budget
    api_family: pthread
    symbol: pthread_mutex_lock
    strict:
      detected: true
      classification: StarvationDetected
      decision_path: Deny
      healing_action: None
      errno: 11
    hardened:
      detected: true
      classification: StarvationDetected
      decision_path: Repair
      healing_action: UpgradeToSafeVariant
      errno: 11
    variants:
      - id: unfair
        params:
          waiters: 8
          max_skips: 3
          grants: [0, 0, 0, 0, 1, 0]
"#;

    #[test]
    fn manifest_parses_yaml_catalog() {
        let manifest = FaultManifest::from_yaml_str(TEST_MANIFEST_YAML).expect("manifest");
        assert_eq!(manifest.schema_version, "v1");
        assert_eq!(manifest.scenarios.len(), 3);
        assert!(manifest.scenario("memory.use_after_free").is_some());
    }

    #[test]
    fn default_executor_detects_use_after_free() {
        let manifest = FaultManifest::from_yaml_str(TEST_MANIFEST_YAML).expect("manifest");
        let scenario = manifest
            .scenario("memory.use_after_free")
            .expect("scenario");
        let variant = scenario.variants.first().expect("variant");
        let mut executor = DefaultFaultExecutor;
        let observation = executor
            .execute_case(scenario, variant)
            .expect("observation");
        assert!(observation.detected);
        assert_eq!(observation.classification, "TemporalViolation");
    }

    #[test]
    fn default_executor_detects_time_drift() {
        let manifest = FaultManifest::from_yaml_str(TEST_MANIFEST_YAML).expect("manifest");
        let scenario = manifest.scenario("time.virtual_drift").expect("scenario");
        let variant = scenario.variants.first().expect("variant");
        let mut executor = DefaultFaultExecutor;
        let observation = executor
            .execute_case(scenario, variant)
            .expect("observation");
        assert!(observation.detected);
        assert_eq!(observation.classification, "ClockDriftExceeded");
    }

    #[test]
    fn default_executor_detects_starvation() {
        let manifest = FaultManifest::from_yaml_str(TEST_MANIFEST_YAML).expect("manifest");
        let scenario = manifest
            .scenario("concurrency.starvation_budget")
            .expect("scenario");
        let variant = scenario.variants.first().expect("variant");
        let mut executor = DefaultFaultExecutor;
        let observation = executor
            .execute_case(scenario, variant)
            .expect("observation");
        assert!(observation.detected);
        assert_eq!(observation.classification, "StarvationDetected");
    }

    #[test]
    fn run_manifest_rejects_unknown_scenario_filter() {
        let manifest = FaultManifest::from_yaml_str(TEST_MANIFEST_YAML).expect("manifest");
        let config = FaultRunConfig::new(std::env::temp_dir().join("fault_injection_test"));
        let err = run_manifest_with_default_executor(
            &manifest,
            Some("missing"),
            &["strict".to_string()],
            &config,
        )
        .expect_err("missing scenario should fail");
        assert!(matches!(err, FaultInjectionError::UnknownScenario(_)));
    }
}
