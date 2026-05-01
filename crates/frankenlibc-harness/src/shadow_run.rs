//! Real-workload shadow-run differential engine for conformance campaigns.
//!
//! This module executes manifest-driven workloads twice:
//! - once against a reference libc environment (host glibc by default)
//! - once against FrankenLibC via `LD_PRELOAD`
//!
//! The resulting report captures:
//! - replay-ready command/env bundles
//! - stdout/stderr/exit-code divergences
//! - optional normalized syscall-trace diffs when `strace` is available
//! - an analysis-side call stack at the divergence point
//! - argument minimization for divergent invocations

use crate::diff;
use crate::structured_log::{
    ArtifactIndex, ArtifactJoinKeys, LogEmitter, LogEntry, LogLevel, Outcome, StreamKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::backtrace::Backtrace;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

const SHADOW_RUN_SCHEMA_VERSION: &str = "v1";
const SHADOW_RUN_BEAD_ID: &str = "bd-2hh.2";
const SHADOW_RUN_EVENT_GATE: &str = "shadow_run";

#[derive(Debug, Error)]
pub enum ShadowRunError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid mode '{0}' for scenario '{1}'")]
    InvalidMode(String, String),
    #[error("scenario '{0}' has no command")]
    MissingCommand(String),
    #[error("command '{0}' not found in PATH")]
    MissingBinary(String),
    #[error(
        "scenario '{scenario_id}' references unresolved placeholder '{placeholder}' in token '{token}'"
    )]
    UnresolvedPlaceholder {
        scenario_id: String,
        placeholder: String,
        token: String,
    },
    #[error("shadow-run execution failed: {0}")]
    Execution(String),
    #[error("unsupported expected_outcome '{outcome}' for scenario '{scenario}' mode '{mode}'")]
    UnsupportedExpectedOutcome {
        scenario: String,
        mode: String,
        outcome: String,
    },
    #[error("unsupported pass_condition '{condition}' for scenario '{scenario}' mode '{mode}'")]
    UnsupportedPassCondition {
        scenario: String,
        mode: String,
        condition: String,
    },
    #[error("scenario '{scenario}' missing required artifact '{artifact}'")]
    MissingRequiredArtifact { scenario: String, artifact: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowReplayDefaults {
    pub seed_key: String,
    pub env_keys: Vec<String>,
    pub deterministic_inputs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowModeExpectation {
    pub expected_outcome: String,
    pub pass_condition: String,
    pub allowed_exit_codes: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowArtifactPolicy {
    pub capture_stdout: bool,
    pub capture_stderr: bool,
    pub capture_env_on_failure: bool,
    pub capture_bundle_on_failure: bool,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowReplaySpec {
    pub seed_key: String,
    pub env_keys: Vec<String>,
    pub deterministic_inputs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowScenario {
    pub id: String,
    #[serde(rename = "class")]
    pub scenario_class: String,
    pub label: String,
    pub priority: u32,
    pub description: String,
    pub command: Vec<String>,
    pub mode_expectations: BTreeMap<String, ShadowModeExpectation>,
    pub artifact_policy: ShadowArtifactPolicy,
    pub replay: ShadowReplaySpec,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowRunManifest {
    pub schema_version: String,
    pub manifest_id: String,
    pub generated_utc: String,
    pub description: String,
    pub replay_defaults: ShadowReplayDefaults,
    pub scenarios: Vec<ShadowScenario>,
}

impl ShadowRunManifest {
    pub fn from_path(path: &Path) -> Result<Self, ShadowRunError> {
        let body = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&body)?)
    }

    #[must_use]
    pub fn shadow_scenarios(&self) -> Vec<&ShadowScenario> {
        self.scenarios
            .iter()
            .filter(|scenario| scenario_is_shadow_run(scenario))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowReplayBundle {
    pub scenario_id: String,
    pub label: String,
    pub mode: String,
    pub reference: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub reference_env: BTreeMap<String, String>,
    pub candidate_env: BTreeMap<String, String>,
    pub replay_key: String,
    pub deterministic_inputs: String,
    pub timeout_ms: u64,
    pub lib_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowArgumentMinimization {
    pub original_command: Vec<String>,
    pub minimized_command: Vec<String>,
    pub evaluations: usize,
    pub removed_argument_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowDivergenceDetail {
    pub mismatch_axes: Vec<String>,
    pub baseline_exit_code: i32,
    pub candidate_exit_code: i32,
    pub stdout_diff: Option<String>,
    pub stderr_diff: Option<String>,
    pub syscall_diff: Option<String>,
    pub analysis_call_stack: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowExecutionSummary {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub duration_ns: u64,
    pub stdout_len: usize,
    pub stderr_len: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowScenarioReport {
    #[serde(default)]
    pub trace_id: String,
    pub scenario_id: String,
    pub label: String,
    pub scenario_class: String,
    pub mode: String,
    pub status: String,
    pub diverged: bool,
    pub reference: String,
    pub reference_run: ShadowExecutionSummary,
    pub candidate_run: ShadowExecutionSummary,
    pub replay: ShadowReplayBundle,
    pub minimization: Option<ShadowArgumentMinimization>,
    pub divergence: Option<ShadowDivergenceDetail>,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowRunSummary {
    pub total_runs: u64,
    pub passed: u64,
    pub diverged: u64,
    pub skipped: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowRunReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub manifest_id: String,
    pub reference: String,
    pub summary: ShadowRunSummary,
    pub scenarios: Vec<ShadowScenarioReport>,
}

#[derive(Debug, Clone)]
pub struct ShadowRunConfig {
    pub workspace_root: PathBuf,
    pub out_dir: PathBuf,
    pub report_path: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
    pub artifact_index_path: Option<PathBuf>,
    pub lib_path: PathBuf,
    pub timeout: Duration,
    pub reference_label: String,
    pub reference_env_overrides: BTreeMap<String, String>,
    pub reference_env_remove: BTreeSet<String>,
    pub capture_syscall_traces: bool,
    pub bead_id: String,
    pub run_id: String,
    pub manifest_ref: Option<String>,
}

impl ShadowRunConfig {
    #[must_use]
    pub fn new(
        workspace_root: PathBuf,
        out_dir: PathBuf,
        lib_path: PathBuf,
        timeout: Duration,
    ) -> Self {
        Self {
            workspace_root,
            out_dir,
            report_path: None,
            log_path: None,
            artifact_index_path: None,
            lib_path,
            timeout,
            reference_label: "glibc".to_string(),
            reference_env_overrides: BTreeMap::new(),
            reference_env_remove: BTreeSet::from([
                "FRANKENLIBC_MODE".to_string(),
                "LD_PRELOAD".to_string(),
            ]),
            capture_syscall_traces: true,
            bead_id: SHADOW_RUN_BEAD_ID.to_string(),
            run_id: "shadow-run".to_string(),
            manifest_ref: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowExecutionArtifacts {
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
    pub exit_code_path: PathBuf,
    pub syscall_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ShadowExecutionRequest {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env_overrides: BTreeMap<String, String>,
    pub env_remove: BTreeSet<String>,
    pub timeout: Duration,
    pub capture_syscall_trace: bool,
    pub artifacts: Option<ShadowExecutionArtifacts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowExecutionResult {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub duration_ns: u64,
    pub syscall_trace: Option<String>,
    pub artifact_refs: Vec<String>,
}

pub trait ShadowCommandExecutor {
    fn execute(
        &mut self,
        request: &ShadowExecutionRequest,
    ) -> Result<ShadowExecutionResult, ShadowRunError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessShadowExecutor;

impl ShadowCommandExecutor for ProcessShadowExecutor {
    fn execute(
        &mut self,
        request: &ShadowExecutionRequest,
    ) -> Result<ShadowExecutionResult, ShadowRunError> {
        if request.argv.is_empty() {
            return Err(ShadowRunError::Execution("empty argv".to_string()));
        }

        let binary = &request.argv[0];
        let mut command = Command::new("timeout");
        command.arg(format_timeout(request.timeout));

        let mut trace_prefix = None;
        if request.capture_syscall_trace && command_exists("strace") {
            let prefix = request
                .artifacts
                .as_ref()
                .and_then(|artifacts| artifacts.syscall_path.as_ref())
                .map(|path| strip_known_extension(path.as_path()))
                .unwrap_or_else(|| request.cwd.join("shadow_syscall_trace"));
            trace_prefix = Some(prefix.clone());
            command
                .arg("strace")
                .arg("-qq")
                .arg("-ff")
                .arg("-ttt")
                .arg("-o")
                .arg(prefix);
        }

        command.arg(binary);
        if request.argv.len() > 1 {
            command.args(&request.argv[1..]);
        }

        command.current_dir(&request.cwd);
        for key in &request.env_remove {
            command.env_remove(key);
        }
        for (key, value) in &request.env_overrides {
            command.env(key, value);
        }

        let started = Instant::now();
        let output = command.output().map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                ShadowRunError::MissingBinary(binary.clone())
            } else {
                ShadowRunError::Io(err)
            }
        })?;
        let duration_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);

        #[cfg(unix)]
        let signal = output.status.signal();
        #[cfg(not(unix))]
        let signal = None;

        let exit_code = output
            .status
            .code()
            .unwrap_or_else(|| 128 + signal.unwrap_or_default());
        let timed_out = exit_code == 124 || exit_code == 125;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        let mut artifact_refs = Vec::new();
        if let Some(artifacts) = &request.artifacts {
            if let Some(parent) = artifacts
                .stdout_path
                .as_ref()
                .and_then(|path| path.parent())
                .or_else(|| {
                    artifacts
                        .stderr_path
                        .as_ref()
                        .and_then(|path| path.parent())
                })
                .or_else(|| {
                    artifacts
                        .syscall_path
                        .as_ref()
                        .and_then(|path| path.parent())
                })
                .or_else(|| artifacts.exit_code_path.parent())
            {
                fs::create_dir_all(parent)?;
            }
            if let Some(path) = &artifacts.stdout_path {
                fs::write(path, stdout.as_bytes())?;
                artifact_refs.push(path_string(path));
            }
            if let Some(path) = &artifacts.stderr_path {
                fs::write(path, stderr.as_bytes())?;
                artifact_refs.push(path_string(path));
            }
            fs::write(&artifacts.exit_code_path, format!("{exit_code}\n"))?;
            artifact_refs.push(path_string(&artifacts.exit_code_path));
        }

        let syscall_trace = trace_prefix
            .as_ref()
            .and_then(|prefix| collect_normalized_strace(prefix).ok())
            .filter(|trace| !trace.is_empty());

        if let (Some(trace), Some(artifacts)) = (&syscall_trace, &request.artifacts)
            && let Some(path) = &artifacts.syscall_path
        {
            fs::write(path, trace.as_bytes())?;
            artifact_refs.push(path_string(path));
        }

        Ok(ShadowExecutionResult {
            exit_code,
            signal,
            timed_out,
            stdout,
            stderr,
            duration_ns,
            syscall_trace,
            artifact_refs,
        })
    }
}

pub fn run_shadow_manifest_with_executor<E: ShadowCommandExecutor>(
    manifest: &ShadowRunManifest,
    modes: &[String],
    config: &ShadowRunConfig,
    executor: &mut E,
) -> Result<ShadowRunReport, ShadowRunError> {
    fs::create_dir_all(&config.out_dir)?;
    let mut emitter = config
        .log_path
        .as_ref()
        .map(|path| {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            LogEmitter::to_file(path, &config.bead_id, &config.run_id)
        })
        .transpose()?;

    let mut reports = Vec::new();
    let mut trace_seq = 0_u64;
    for scenario in manifest.shadow_scenarios() {
        for mode in modes {
            trace_seq = trace_seq.saturating_add(1);
            let trace_id = shadow_trace_id(&config.bead_id, &config.run_id, trace_seq);
            reports.push(run_shadow_scenario_with_executor(
                scenario,
                mode,
                config,
                executor,
                emitter.as_mut(),
                &trace_id,
            )?);
        }
    }

    if let Some(log) = emitter.as_mut() {
        log.flush()?;
    }

    reports.sort_by(|a, b| {
        a.scenario_class
            .cmp(&b.scenario_class)
            .then_with(|| a.scenario_id.cmp(&b.scenario_id))
            .then_with(|| a.mode.cmp(&b.mode))
    });

    let total_runs = u64::try_from(reports.len()).unwrap_or(0);
    let passed =
        u64::try_from(reports.iter().filter(|row| row.status == "pass").count()).unwrap_or(0);
    let diverged = u64::try_from(
        reports
            .iter()
            .filter(|row| row.status == "diverged")
            .count(),
    )
    .unwrap_or(0);
    let skipped =
        u64::try_from(reports.iter().filter(|row| row.status == "skipped").count()).unwrap_or(0);
    let errors = total_runs
        .saturating_sub(passed)
        .saturating_sub(diverged)
        .saturating_sub(skipped);

    let report = ShadowRunReport {
        schema_version: SHADOW_RUN_SCHEMA_VERSION.to_string(),
        bead: config.bead_id.clone(),
        generated_at_utc: now_utc(),
        manifest_id: manifest.manifest_id.clone(),
        reference: config.reference_label.clone(),
        summary: ShadowRunSummary {
            total_runs,
            passed,
            diverged,
            skipped,
            errors,
        },
        scenarios: reports,
    };

    if let Some(path) = &config.report_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_json_pretty(path, &report)?;
        write_shadow_markdown_report(&companion_markdown_path(path), &report)?;
    }

    if let Some(path) = &config.artifact_index_path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_shadow_artifact_index(path, config, &report)?;
    }

    Ok(report)
}

pub fn run_shadow_scenario_with_executor<E: ShadowCommandExecutor>(
    scenario: &ShadowScenario,
    mode: &str,
    config: &ShadowRunConfig,
    executor: &mut E,
    mut emitter: Option<&mut LogEmitter>,
    trace_id: &str,
) -> Result<ShadowScenarioReport, ShadowRunError> {
    if scenario.command.is_empty() {
        return Err(ShadowRunError::MissingCommand(scenario.id.clone()));
    }
    let Some(expectation) = scenario.mode_expectations.get(mode) else {
        return Err(ShadowRunError::InvalidMode(
            mode.to_string(),
            scenario.id.clone(),
        ));
    };

    let case_dir = config
        .out_dir
        .join(&scenario.scenario_class)
        .join(mode)
        .join(&scenario.label);
    fs::create_dir_all(&case_dir)?;

    let resolved_command = resolve_shadow_command(scenario, config)?;
    let reference_env = build_reference_env(scenario, config);
    let candidate_env = build_candidate_env(scenario, mode, config);
    let replay_key = build_replay_key(
        &scenario.id,
        &resolved_command,
        mode,
        &candidate_env,
        &config.workspace_root,
    );
    let replay = ShadowReplayBundle {
        scenario_id: scenario.id.clone(),
        label: scenario.label.clone(),
        mode: mode.to_string(),
        reference: config.reference_label.clone(),
        command: resolved_command.clone(),
        cwd: path_string(&config.workspace_root),
        reference_env: replay_env_bundle(&reference_env, &scenario.replay),
        candidate_env: replay_env_bundle(&candidate_env, &scenario.replay),
        replay_key,
        deterministic_inputs: scenario.replay.deterministic_inputs.clone(),
        timeout_ms: u64::try_from(config.timeout.as_millis()).unwrap_or(u64::MAX),
        lib_path: path_string(&config.lib_path),
    };

    if let Some(binary) = resolve_command_binary(&resolved_command)
        && !binary_exists(binary)
    {
        if scenario_is_optional_binary(scenario) {
            if let Some(log) = emitter.as_mut() {
                emit_shadow_skip_log(log, scenario, mode, &replay, binary, trace_id)?;
            }
            return Ok(skipped_shadow_report(
                scenario,
                mode,
                config,
                replay,
                format!("optional binary missing: {binary}"),
                trace_id.to_string(),
            ));
        }
        return Err(ShadowRunError::MissingBinary(binary.to_string()));
    }

    let baseline_request = ShadowExecutionRequest {
        argv: resolved_command.clone(),
        cwd: config.workspace_root.clone(),
        env_overrides: reference_env.clone(),
        env_remove: config.reference_env_remove.clone(),
        timeout: config.timeout,
        capture_syscall_trace: config.capture_syscall_traces,
        artifacts: Some(ShadowExecutionArtifacts {
            stdout_path: scenario
                .artifact_policy
                .capture_stdout
                .then(|| case_dir.join("baseline.stdout.txt")),
            stderr_path: scenario
                .artifact_policy
                .capture_stderr
                .then(|| case_dir.join("baseline.stderr.txt")),
            exit_code_path: case_dir.join("baseline.exit_code"),
            syscall_path: Some(case_dir.join("baseline.syscall.txt")),
        }),
    };
    let baseline = executor.execute(&baseline_request)?;

    let candidate_request = ShadowExecutionRequest {
        argv: resolved_command,
        cwd: config.workspace_root.clone(),
        env_overrides: candidate_env.clone(),
        env_remove: config.reference_env_remove.clone(),
        timeout: config.timeout,
        capture_syscall_trace: config.capture_syscall_traces,
        artifacts: Some(ShadowExecutionArtifacts {
            stdout_path: scenario
                .artifact_policy
                .capture_stdout
                .then(|| case_dir.join("stdout.txt")),
            stderr_path: scenario
                .artifact_policy
                .capture_stderr
                .then(|| case_dir.join("stderr.txt")),
            exit_code_path: case_dir.join("exit_code"),
            syscall_path: Some(case_dir.join("syscall.txt")),
        }),
    };
    let candidate = executor.execute(&candidate_request)?;

    let mut artifact_refs = baseline.artifact_refs.clone();
    artifact_refs.extend(candidate.artifact_refs.iter().cloned());
    artifact_refs.sort();
    artifact_refs.dedup();

    let divergence = build_divergence(&baseline, &candidate);
    let baseline_allowed = expectation.allowed_exit_codes.contains(&baseline.exit_code);
    let candidate_allowed = expectation
        .allowed_exit_codes
        .contains(&candidate.exit_code);
    let observed_outcome = if divergence.is_some() {
        "diverged"
    } else {
        "pass"
    };
    let expected_outcome_satisfied =
        evaluate_expected_outcome(expectation, observed_outcome, scenario, mode)?;
    let pass_condition_satisfied =
        evaluate_pass_condition(expectation, &baseline, &candidate, scenario, mode)?;
    let mut minimization = None;
    let status = if !baseline_allowed {
        "baseline_error".to_string()
    } else if !candidate_allowed {
        "expectation_failed".to_string()
    } else if let Some(detail) = divergence.as_ref() {
        minimization =
            minimize_divergent_command(scenario, mode, config, executor, &detail.mismatch_axes)?;
        if let Some(minimized) = &minimization {
            let path = case_dir.join("shadow_minimized_replay.json");
            fs::write(&path, serde_json::to_string_pretty(minimized)?)?;
            artifact_refs.push(path_string(&path));
        }

        if expected_outcome_satisfied {
            "pass".to_string()
        } else {
            "diverged".to_string()
        }
    } else if expected_outcome_satisfied && pass_condition_satisfied {
        "pass".to_string()
    } else {
        "expectation_failed".to_string()
    };

    if status != "pass" && scenario.artifact_policy.capture_bundle_on_failure {
        let replay_path = case_dir.join("shadow_replay_bundle.json");
        fs::write(&replay_path, serde_json::to_string_pretty(&replay)?)?;
        artifact_refs.push(path_string(&replay_path));

        if let Some(detail) = divergence.as_ref() {
            let divergence_path = case_dir.join("shadow_divergence_report.json");
            fs::write(&divergence_path, serde_json::to_string_pretty(detail)?)?;
            artifact_refs.push(path_string(&divergence_path));
        }
    }

    if status != "pass" && scenario.artifact_policy.capture_env_on_failure {
        let baseline_env_path = case_dir.join("baseline.env.json");
        fs::write(
            &baseline_env_path,
            serde_json::to_string_pretty(&reference_env)?,
        )?;
        artifact_refs.push(path_string(&baseline_env_path));

        let candidate_env_path = case_dir.join("candidate.env.json");
        fs::write(
            &candidate_env_path,
            serde_json::to_string_pretty(&candidate_env)?,
        )?;
        artifact_refs.push(path_string(&candidate_env_path));
    }

    artifact_refs.sort();
    artifact_refs.dedup();
    ensure_required_artifacts_exist(scenario, &case_dir)?;

    if let Some(log) = emitter.as_mut() {
        emit_shadow_log(
            log,
            &ShadowLogContext {
                scenario,
                mode,
                status: &status,
                baseline: &baseline,
                candidate: &candidate,
                divergence: divergence.as_ref(),
                artifact_refs: &artifact_refs,
                replay: &replay,
                trace_id,
            },
        )?;
    }

    Ok(ShadowScenarioReport {
        trace_id: trace_id.to_string(),
        scenario_id: scenario.id.clone(),
        label: scenario.label.clone(),
        scenario_class: scenario.scenario_class.clone(),
        mode: mode.to_string(),
        status: status.clone(),
        diverged: divergence.is_some(),
        reference: config.reference_label.clone(),
        reference_run: summarize_execution(&baseline),
        candidate_run: summarize_execution(&candidate),
        replay,
        minimization,
        divergence,
        artifact_refs,
    })
}

fn ensure_required_artifacts_exist(
    scenario: &ShadowScenario,
    case_dir: &Path,
) -> Result<(), ShadowRunError> {
    for artifact in &scenario.artifact_policy.required_artifacts {
        if !case_dir.join(artifact).exists() {
            return Err(ShadowRunError::MissingRequiredArtifact {
                scenario: scenario.id.clone(),
                artifact: artifact.clone(),
            });
        }
    }
    Ok(())
}

fn evaluate_expected_outcome(
    expectation: &ShadowModeExpectation,
    observed_outcome: &str,
    scenario: &ShadowScenario,
    mode: &str,
) -> Result<bool, ShadowRunError> {
    match expectation.expected_outcome.as_str() {
        "pass" | "diverged" => Ok(expectation.expected_outcome == observed_outcome),
        outcome => Err(ShadowRunError::UnsupportedExpectedOutcome {
            scenario: scenario.id.clone(),
            mode: mode.to_string(),
            outcome: outcome.to_string(),
        }),
    }
}

fn scenario_is_shadow_run(scenario: &ShadowScenario) -> bool {
    let lower_description = scenario.description.to_ascii_lowercase();
    let has_baseline_artifact = scenario
        .artifact_policy
        .required_artifacts
        .iter()
        .any(|artifact| artifact.starts_with("baseline."));
    has_baseline_artifact
        || lower_description.contains("shadow-run")
        || lower_description.contains("shadow run")
        || scenario.label.contains("shadow")
}

fn build_reference_env(
    scenario: &ShadowScenario,
    config: &ShadowRunConfig,
) -> BTreeMap<String, String> {
    let mut env = config.reference_env_overrides.clone();
    for key in &scenario.replay.env_keys {
        if config.reference_env_remove.contains(key) {
            continue;
        }
        if let Ok(value) = std::env::var(key) {
            env.entry(key.clone()).or_insert(value);
        }
    }
    env
}

fn build_candidate_env(
    scenario: &ShadowScenario,
    mode: &str,
    config: &ShadowRunConfig,
) -> BTreeMap<String, String> {
    let mut env = build_reference_env(scenario, config);
    env.insert("FRANKENLIBC_MODE".to_string(), mode.to_string());
    env.insert("LD_PRELOAD".to_string(), path_string(&config.lib_path));
    env
}

fn replay_env_bundle(
    env: &BTreeMap<String, String>,
    replay: &ShadowReplaySpec,
) -> BTreeMap<String, String> {
    replay
        .env_keys
        .iter()
        .filter_map(|key| env.get(key).map(|value| (key.clone(), value.clone())))
        .collect()
}

fn build_replay_key(
    scenario_id: &str,
    command: &[String],
    mode: &str,
    env: &BTreeMap<String, String>,
    cwd: &Path,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scenario_id.as_bytes());
    hasher.update([0]);
    hasher.update(mode.as_bytes());
    hasher.update([0]);
    hasher.update(path_string(cwd).as_bytes());
    hasher.update([0]);
    for arg in command {
        hasher.update(arg.as_bytes());
        hasher.update([0]);
    }
    for (key, value) in env {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    hex_digest(&hasher.finalize())[..16].to_string()
}

struct ShadowLogContext<'a> {
    scenario: &'a ShadowScenario,
    mode: &'a str,
    status: &'a str,
    baseline: &'a ShadowExecutionResult,
    candidate: &'a ShadowExecutionResult,
    divergence: Option<&'a ShadowDivergenceDetail>,
    artifact_refs: &'a [String],
    replay: &'a ShadowReplayBundle,
    trace_id: &'a str,
}

fn emit_shadow_log(
    emitter: &mut LogEmitter,
    context: &ShadowLogContext<'_>,
) -> Result<(), ShadowRunError> {
    let outcome = match context.status {
        "pass" => Outcome::Pass,
        "skipped" => Outcome::Skip,
        "diverged" => Outcome::Fail,
        _ => Outcome::Error,
    };
    let total_latency = context
        .baseline
        .duration_ns
        .saturating_add(context.candidate.duration_ns);
    let event = match context.status {
        "pass" => "conformance.shadow_run_match",
        "skipped" => "conformance.shadow_run_skip",
        "diverged" => "conformance.shadow_run_divergence",
        "baseline_error" => "conformance.shadow_run_baseline_error",
        "expectation_failed" => "conformance.shadow_run_expectation_failed",
        _ => "conformance.shadow_run_error",
    };
    let level = match context.status {
        "pass" => LogLevel::Info,
        "skipped" => LogLevel::Warn,
        "diverged" | "baseline_error" | "expectation_failed" => LogLevel::Error,
        _ => LogLevel::Error,
    };
    let mismatch_axes = context
        .divergence
        .map(|detail| detail.mismatch_axes.clone())
        .unwrap_or_default();
    emitter.emit_entry(
        LogEntry::new(context.trace_id, level, event)
            .with_stream(StreamKind::Conformance)
            .with_gate(SHADOW_RUN_EVENT_GATE)
            .with_mode(context.mode.to_string())
            .with_api(
                context.scenario.scenario_class.clone(),
                context.scenario.id.clone(),
            )
            .with_outcome(outcome)
            .with_errno(0)
            .with_latency_ns(total_latency)
            .with_healing_action("none")
            .with_artifacts(context.artifact_refs.to_vec())
            .with_details(serde_json::json!({
                "label": context.scenario.label,
                "reference": context.replay.reference,
                "replay_key": context.replay.replay_key,
                "baseline_exit_code": context.baseline.exit_code,
                "candidate_exit_code": context.candidate.exit_code,
                "mismatch_axes": mismatch_axes,
                "decision_path": "conformance->shadow_run->compare"
            })),
    )?;
    Ok(())
}

fn emit_shadow_skip_log(
    emitter: &mut LogEmitter,
    scenario: &ShadowScenario,
    mode: &str,
    replay: &ShadowReplayBundle,
    required_binary: &str,
    trace_id: &str,
) -> Result<(), ShadowRunError> {
    emitter.emit_entry(
        LogEntry::new(trace_id, LogLevel::Warn, "conformance.shadow_run_skip")
            .with_stream(StreamKind::Conformance)
            .with_gate(SHADOW_RUN_EVENT_GATE)
            .with_mode(mode.to_string())
            .with_api(scenario.scenario_class.clone(), scenario.id.clone())
            .with_outcome(Outcome::Skip)
            .with_errno(0)
            .with_latency_ns(0)
            .with_healing_action("none")
            .with_artifacts(Vec::new())
            .with_details(serde_json::json!({
                "label": scenario.label,
                "reference": replay.reference,
                "replay_key": replay.replay_key,
                "required_binary": required_binary,
                "decision_path": "conformance->shadow_run->skip_optional_binary"
            })),
    )?;
    Ok(())
}

fn summarize_execution(result: &ShadowExecutionResult) -> ShadowExecutionSummary {
    ShadowExecutionSummary {
        exit_code: result.exit_code,
        signal: result.signal,
        timed_out: result.timed_out,
        duration_ns: result.duration_ns,
        stdout_len: result.stdout.len(),
        stderr_len: result.stderr.len(),
    }
}

fn build_divergence(
    baseline: &ShadowExecutionResult,
    candidate: &ShadowExecutionResult,
) -> Option<ShadowDivergenceDetail> {
    let mut mismatch_axes = Vec::new();
    let stdout_diff = if baseline.stdout != candidate.stdout {
        mismatch_axes.push("stdout".to_string());
        Some(diff::render_diff(&baseline.stdout, &candidate.stdout))
    } else {
        None
    };
    let stderr_diff = if baseline.stderr != candidate.stderr {
        mismatch_axes.push("stderr".to_string());
        Some(diff::render_diff(&baseline.stderr, &candidate.stderr))
    } else {
        None
    };
    let syscall_diff = match (&baseline.syscall_trace, &candidate.syscall_trace) {
        (Some(reference), Some(candidate_trace)) if reference != candidate_trace => {
            mismatch_axes.push("syscall_trace".to_string());
            Some(diff::render_diff(reference, candidate_trace))
        }
        _ => None,
    };
    if baseline.exit_code != candidate.exit_code {
        mismatch_axes.push("exit_code".to_string());
    }

    if mismatch_axes.is_empty() {
        None
    } else {
        Some(ShadowDivergenceDetail {
            mismatch_axes,
            baseline_exit_code: baseline.exit_code,
            candidate_exit_code: candidate.exit_code,
            stdout_diff,
            stderr_diff,
            syscall_diff,
            analysis_call_stack: Some(Backtrace::force_capture().to_string()),
        })
    }
}

fn skipped_shadow_report(
    scenario: &ShadowScenario,
    mode: &str,
    config: &ShadowRunConfig,
    replay: ShadowReplayBundle,
    reason: String,
    trace_id: String,
) -> ShadowScenarioReport {
    ShadowScenarioReport {
        trace_id,
        scenario_id: scenario.id.clone(),
        label: scenario.label.clone(),
        scenario_class: scenario.scenario_class.clone(),
        mode: mode.to_string(),
        status: "skipped".to_string(),
        diverged: false,
        reference: config.reference_label.clone(),
        reference_run: ShadowExecutionSummary {
            exit_code: 0,
            signal: None,
            timed_out: false,
            duration_ns: 0,
            stdout_len: 0,
            stderr_len: 0,
        },
        candidate_run: ShadowExecutionSummary {
            exit_code: 0,
            signal: None,
            timed_out: false,
            duration_ns: 0,
            stdout_len: 0,
            stderr_len: 0,
        },
        replay,
        minimization: None,
        divergence: Some(ShadowDivergenceDetail {
            mismatch_axes: vec!["skip".to_string()],
            baseline_exit_code: 0,
            candidate_exit_code: 0,
            stdout_diff: None,
            stderr_diff: None,
            syscall_diff: None,
            analysis_call_stack: Some(reason),
        }),
        artifact_refs: Vec::new(),
    }
}

fn write_shadow_artifact_index(
    path: &Path,
    config: &ShadowRunConfig,
    report: &ShadowRunReport,
) -> Result<(), ShadowRunError> {
    let mut artifact_index = ArtifactIndex::new(config.run_id.clone(), config.bead_id.clone());
    let mut seen_paths = BTreeSet::new();

    if let Some(log_path) = &config.log_path {
        let resolved = resolve_workspace_path(&config.workspace_root, log_path);
        if resolved.exists() {
            let recorded = path_string(log_path);
            artifact_index.add(recorded.clone(), "log", sha256_path(&resolved)?);
            seen_paths.insert(recorded);
        }
    }

    if let Some(report_path) = &config.report_path {
        let resolved = resolve_workspace_path(&config.workspace_root, report_path);
        if resolved.exists() {
            let recorded = path_string(report_path);
            artifact_index.add(recorded.clone(), "report", sha256_path(&resolved)?);
            seen_paths.insert(recorded);
        }

        let markdown_path = companion_markdown_path(report_path);
        let resolved_markdown = resolve_workspace_path(&config.workspace_root, &markdown_path);
        if resolved_markdown.exists() {
            let recorded = path_string(&markdown_path);
            artifact_index.add(
                recorded.clone(),
                "report_human",
                sha256_path(&resolved_markdown)?,
            );
            seen_paths.insert(recorded);
        }
    }

    if let Some(manifest_ref) = &config.manifest_ref {
        let resolved = resolve_workspace_path(&config.workspace_root, Path::new(manifest_ref));
        if resolved.exists() {
            let recorded = manifest_ref.clone();
            artifact_index.add(recorded.clone(), "manifest", sha256_path(&resolved)?);
            seen_paths.insert(recorded);
        }
    }

    for scenario in &report.scenarios {
        let join_keys = ArtifactJoinKeys {
            trace_ids: vec![scenario.trace_id.clone()],
            ..ArtifactJoinKeys::default()
        };
        for artifact_ref in &scenario.artifact_refs {
            if !seen_paths.insert(artifact_ref.clone()) {
                continue;
            }
            let resolved = resolve_workspace_path(&config.workspace_root, Path::new(artifact_ref));
            artifact_index.add_with_join_keys(
                artifact_ref.clone(),
                shadow_artifact_kind(&resolved),
                sha256_path(&resolved)?,
                join_keys.clone(),
            );
        }
    }

    write_json_pretty(path, &artifact_index)
}

fn resolve_workspace_path(workspace_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

fn shadow_artifact_kind(path: &Path) -> String {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("baseline.stdout.txt") | Some("stdout.txt") => "stdout".to_string(),
        Some("baseline.stderr.txt") | Some("stderr.txt") => "stderr".to_string(),
        Some("baseline.exit_code") | Some("exit_code") => "exit_code".to_string(),
        Some("baseline.syscall.txt") | Some("syscall.txt") => "syscall_trace".to_string(),
        Some("shadow_replay_bundle.json") => "replay_bundle".to_string(),
        Some("shadow_divergence_report.json") => "divergence_report".to_string(),
        Some("shadow_minimized_replay.json") => "minimized_replay".to_string(),
        Some("baseline.env.json") | Some("candidate.env.json") => "environment".to_string(),
        _ => "artifact".to_string(),
    }
}

fn shadow_trace_id(bead_id: &str, run_id: &str, seq: u64) -> String {
    format!("{bead_id}::{run_id}::{seq:03}")
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), ShadowRunError> {
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn companion_markdown_path(path: &Path) -> PathBuf {
    let mut markdown = path.to_path_buf();
    if markdown.extension().is_some() {
        markdown.set_extension("md");
        markdown
    } else {
        let mut os = markdown.into_os_string();
        os.push(".md");
        PathBuf::from(os)
    }
}

fn write_shadow_markdown_report(
    path: &Path,
    report: &ShadowRunReport,
) -> Result<(), ShadowRunError> {
    let mut body = String::new();
    body.push_str("# Shadow Run Report\n\n");
    body.push_str(&format!(
        "- Generated: {}\n- Bead: `{}`\n- Manifest: `{}`\n- Reference: `{}`\n\n",
        report.generated_at_utc, report.bead, report.manifest_id, report.reference
    ));
    body.push_str("## Summary\n\n");
    body.push_str("| Total | Passed | Diverged | Skipped | Errors |\n");
    body.push_str("| --- | --- | --- | --- | --- |\n");
    body.push_str(&format!(
        "| {} | {} | {} | {} | {} |\n\n",
        report.summary.total_runs,
        report.summary.passed,
        report.summary.diverged,
        report.summary.skipped,
        report.summary.errors
    ));

    body.push_str("## Scenario Matrix\n\n");
    body.push_str("| Scenario | Mode | Status | Baseline RC | Candidate RC | Mismatch Axes |\n");
    body.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for scenario in &report.scenarios {
        let mismatch_axes = scenario
            .divergence
            .as_ref()
            .map(|detail| detail.mismatch_axes.join(", "))
            .filter(|axes| !axes.is_empty())
            .unwrap_or_else(|| "-".to_string());
        body.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} |\n",
            scenario.scenario_id,
            scenario.mode,
            scenario.status,
            scenario.reference_run.exit_code,
            scenario.candidate_run.exit_code,
            mismatch_axes
        ));
    }

    let divergent = report
        .scenarios
        .iter()
        .filter(|scenario| scenario.status != "pass")
        .collect::<Vec<_>>();
    if divergent.is_empty() {
        body.push_str("\n## Divergences\n\nNo scenario mismatches were recorded.\n");
    } else {
        body.push_str("\n## Divergences\n");
        for scenario in divergent {
            body.push_str(&format!(
                "\n### `{}` `{}`\n\n- Status: `{}`\n- Trace: `{}`\n- Baseline exit: `{}`\n- Candidate exit: `{}`\n",
                scenario.scenario_id,
                scenario.mode,
                scenario.status,
                scenario.trace_id,
                scenario.reference_run.exit_code,
                scenario.candidate_run.exit_code
            ));
            if let Some(detail) = &scenario.divergence {
                body.push_str(&format!(
                    "- Mismatch axes: {}\n",
                    if detail.mismatch_axes.is_empty() {
                        "-".to_string()
                    } else {
                        detail.mismatch_axes.join(", ")
                    }
                ));
                append_optional_markdown_block(
                    &mut body,
                    "stdout diff",
                    detail.stdout_diff.as_deref(),
                );
                append_optional_markdown_block(
                    &mut body,
                    "stderr diff",
                    detail.stderr_diff.as_deref(),
                );
                append_optional_markdown_block(
                    &mut body,
                    "syscall diff",
                    detail.syscall_diff.as_deref(),
                );
                append_optional_markdown_block(
                    &mut body,
                    "analysis call stack",
                    detail.analysis_call_stack.as_deref(),
                );
            }
            if let Some(minimization) = &scenario.minimization {
                body.push_str("\nMinimized replay command:\n\n```text\n");
                body.push_str(&minimization.minimized_command.join(" "));
                body.push_str("\n```\n");
            }
            if !scenario.artifact_refs.is_empty() {
                body.push_str("\nArtifacts:\n");
                for artifact in &scenario.artifact_refs {
                    body.push_str(&format!("- `{artifact}`\n"));
                }
            }
        }
    }

    fs::write(path, body)?;
    Ok(())
}

fn append_optional_markdown_block(body: &mut String, title: &str, content: Option<&str>) {
    if let Some(content) = content
        && !content.trim().is_empty()
    {
        body.push_str(&format!(
            "\n{}:\n\n```text\n{}\n```\n",
            title,
            content.trim_end()
        ));
    }
}

fn sha256_path(path: &Path) -> Result<String, ShadowRunError> {
    let bytes = fs::read(path)?;
    Ok(hex_digest(&Sha256::digest(&bytes)))
}

fn evaluate_pass_condition(
    expectation: &ShadowModeExpectation,
    baseline: &ShadowExecutionResult,
    candidate: &ShadowExecutionResult,
    scenario: &ShadowScenario,
    mode: &str,
) -> Result<bool, ShadowRunError> {
    let mut normalized = expectation
        .pass_condition
        .split("and")
        .map(str::trim)
        .filter(|clause| !clause.is_empty());
    normalized.try_fold(true, |acc, clause| {
        Ok(acc && evaluate_pass_clause(clause, baseline, candidate, scenario, mode)?)
    })
}

fn evaluate_pass_clause(
    clause: &str,
    baseline: &ShadowExecutionResult,
    candidate: &ShadowExecutionResult,
    scenario: &ShadowScenario,
    mode: &str,
) -> Result<bool, ShadowRunError> {
    let normalized: String = clause
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if let Some(raw) = normalized.strip_prefix("exit_code==") {
        return raw
            .parse::<i32>()
            .map(|expected| candidate.exit_code == expected)
            .map_err(|_| unsupported_pass_condition_error(clause, scenario, mode));
    }
    if let Some(raw) = normalized.strip_prefix("all_iterations_exit_code==") {
        return raw
            .parse::<i32>()
            .map(|expected| candidate.exit_code == expected)
            .map_err(|_| unsupported_pass_condition_error(clause, scenario, mode));
    }
    match normalized.as_str() {
        "baseline_stdout==stdout" => Ok(baseline.stdout == candidate.stdout),
        "baseline_stderr==stderr" => Ok(baseline.stderr == candidate.stderr),
        "baseline_exit_code==exit_code" => Ok(baseline.exit_code == candidate.exit_code),
        "baseline_syscall_trace==syscall_trace" => {
            Ok(baseline.syscall_trace == candidate.syscall_trace)
        }
        _ => Err(unsupported_pass_condition_error(clause, scenario, mode)),
    }
}

fn unsupported_pass_condition_error(
    clause: &str,
    scenario: &ShadowScenario,
    mode: &str,
) -> ShadowRunError {
    ShadowRunError::UnsupportedPassCondition {
        scenario: scenario.id.clone(),
        mode: mode.to_string(),
        condition: clause.to_string(),
    }
}

fn minimize_divergent_command<E: ShadowCommandExecutor>(
    scenario: &ShadowScenario,
    mode: &str,
    config: &ShadowRunConfig,
    executor: &mut E,
    mismatch_axes: &[String],
) -> Result<Option<ShadowArgumentMinimization>, ShadowRunError> {
    if scenario.command.len() <= 2 {
        return Ok(None);
    }
    let program = scenario.command[0].clone();
    let original_tail = scenario.command[1..].to_vec();
    let primary_axis = mismatch_axes
        .first()
        .cloned()
        .unwrap_or_else(|| "stdout".to_string());

    let reference_env = build_reference_env(scenario, config);
    let candidate_env = build_candidate_env(scenario, mode, config);
    let mut evaluations = 0usize;
    let minimized_tail = ddmin_items(&original_tail, |tail| {
        evaluations += 1;
        let mut argv = vec![program.clone()];
        argv.extend_from_slice(tail);
        let baseline = executor.execute(&ShadowExecutionRequest {
            argv: argv.clone(),
            cwd: config.workspace_root.clone(),
            env_overrides: reference_env.clone(),
            env_remove: config.reference_env_remove.clone(),
            timeout: config.timeout,
            capture_syscall_trace: false,
            artifacts: None,
        });
        let candidate = executor.execute(&ShadowExecutionRequest {
            argv,
            cwd: config.workspace_root.clone(),
            env_overrides: candidate_env.clone(),
            env_remove: config.reference_env_remove.clone(),
            timeout: config.timeout,
            capture_syscall_trace: false,
            artifacts: None,
        });

        match (baseline, candidate) {
            (Ok(reference), Ok(candidate_run)) if reference.exit_code == 0 => {
                build_divergence(&reference, &candidate_run).is_some_and(|detail| {
                    detail
                        .mismatch_axes
                        .iter()
                        .any(|axis| axis == &primary_axis)
                })
            }
            _ => false,
        }
    });

    if minimized_tail.len() == original_tail.len() {
        return Ok(None);
    }

    let mut minimized_command = vec![program];
    minimized_command.extend(minimized_tail.clone());
    Ok(Some(ShadowArgumentMinimization {
        original_command: scenario.command.clone(),
        minimized_command,
        evaluations,
        removed_argument_count: original_tail.len().saturating_sub(minimized_tail.len()),
    }))
}

fn ddmin_items<F>(items: &[String], mut predicate: F) -> Vec<String>
where
    F: FnMut(&[String]) -> bool,
{
    if items.is_empty() || !predicate(items) {
        return items.to_vec();
    }

    let mut current = items.to_vec();
    let mut n = 2usize;
    loop {
        let len = current.len();
        if n > len {
            break;
        }
        let chunk_size = len.div_ceil(n);
        let mut next_current = None;
        let mut next_n = n;

        let mut i = 0usize;
        while i < n {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(len);
            if start >= len {
                break;
            }
            let candidate = current[start..end].to_vec();
            if !candidate.is_empty() && predicate(&candidate) {
                next_current = Some(candidate);
                next_n = 2;
                break;
            }
            i += 1;
        }

        if let Some(candidate) = next_current {
            current = candidate;
            n = next_n;
            continue;
        }

        let mut i = 0usize;
        while i < n {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(len);
            if start >= len {
                break;
            }
            let candidate: Vec<String> = current[..start]
                .iter()
                .chain(current[end..].iter())
                .cloned()
                .collect();
            if candidate.is_empty() {
                i += 1;
                continue;
            }
            if predicate(&candidate) {
                next_current = Some(candidate);
                next_n = n.saturating_sub(1).max(2);
                break;
            }
            i += 1;
        }

        if let Some(candidate) = next_current {
            current = candidate;
            n = next_n;
            continue;
        }

        if n >= len {
            break;
        }
        n = (n * 2).min(len);
    }
    current
}

fn collect_normalized_strace(prefix: &Path) -> Result<String, ShadowRunError> {
    let parent = prefix.parent().unwrap_or_else(|| Path::new("."));
    let needle = prefix
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut fragments = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
            continue;
        };
        if name.starts_with(&needle) {
            fragments.push(path);
        }
    }
    fragments.sort();

    let mut combined = Vec::new();
    for path in fragments {
        let body = fs::read_to_string(&path)?;
        combined.push(normalize_strace_output(&body));
    }
    Ok(combined.join("\n"))
}

fn normalize_strace_output(raw: &str) -> String {
    raw.lines()
        .map(normalize_strace_line)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_strace_line(raw: &str) -> String {
    let line = raw.trim();
    if line.is_empty() {
        return String::new();
    }

    let mut tokens = line.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        return String::new();
    }
    if tokens
        .first()
        .is_some_and(|token| token.chars().all(|ch| ch.is_ascii_digit()))
    {
        tokens.remove(0);
    }
    if tokens
        .first()
        .is_some_and(|token| is_numeric_timestamp_token(token))
    {
        tokens.remove(0);
    }
    tokens.join(" ")
}

fn is_numeric_timestamp_token(token: &str) -> bool {
    token
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == '.' || ch == ':')
        && token.chars().any(|ch| ch == '.' || ch == ':')
}

fn command_exists(binary: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!(
            "command -v {} >/dev/null 2>&1",
            shell_escape(binary)
        ))
        .status()
        .is_ok_and(|status| status.success())
}

fn resolve_shadow_command(
    scenario: &ShadowScenario,
    config: &ShadowRunConfig,
) -> Result<Vec<String>, ShadowRunError> {
    scenario
        .command
        .iter()
        .map(|token| resolve_shadow_token(token, scenario, config))
        .collect()
}

fn resolve_shadow_token(
    token: &str,
    scenario: &ShadowScenario,
    config: &ShadowRunConfig,
) -> Result<String, ShadowRunError> {
    let mut resolved = String::new();
    let mut cursor = token;
    while let Some(start) = cursor.find("${") {
        resolved.push_str(&cursor[..start]);
        let rest = &cursor[start + 2..];
        let Some(end) = rest.find('}') else {
            break;
        };
        let placeholder = &rest[..end];
        let replacement = if let Ok(value) = std::env::var(placeholder) {
            value
        } else if let Some(value) = synthesized_placeholder(placeholder, config)? {
            value
        } else {
            return Err(ShadowRunError::UnresolvedPlaceholder {
                scenario_id: scenario.id.clone(),
                placeholder: placeholder.to_string(),
                token: token.to_string(),
            });
        };
        resolved.push_str(&replacement);
        cursor = &rest[end + 1..];
    }
    resolved.push_str(cursor);
    Ok(resolved)
}

fn synthesized_placeholder(
    placeholder: &str,
    config: &ShadowRunConfig,
) -> Result<Option<String>, ShadowRunError> {
    match placeholder {
        "SMOKE_FIXTURE" => {
            let fixture_path = config
                .out_dir
                .join("fixtures")
                .join("smoke_shadow_input.txt");
            if !fixture_path.exists() {
                if let Some(parent) = fixture_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&fixture_path, b"charlie\nalpha\nbravo\nalpha\n")?;
            }
            Ok(Some(path_string(&fixture_path)))
        }
        _ => Ok(None),
    }
}

fn resolve_command_binary(argv: &[String]) -> Option<&str> {
    let first = argv.first()?;
    if is_env_wrapper(first) {
        argv.iter()
            .skip(1)
            .find(|token| !looks_like_env_assignment(token))
            .map(String::as_str)
    } else {
        Some(first.as_str())
    }
}

fn is_env_wrapper(binary: &str) -> bool {
    Path::new(binary)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "env")
}

fn looks_like_env_assignment(token: &str) -> bool {
    let Some((key, _value)) = token.split_once('=') else {
        return false;
    };
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn binary_exists(binary: &str) -> bool {
    if binary.contains('/') {
        Path::new(binary).exists()
    } else {
        command_exists(binary)
    }
}

fn scenario_is_optional_binary(scenario: &ShadowScenario) -> bool {
    let description = scenario.description.to_ascii_lowercase();
    description.contains("optional scenario only when")
        || description.starts_with("optional ")
        || description.contains("optional shadow-run parity check")
}

fn shell_escape(raw: &str) -> String {
    raw.replace('\'', "'\"'\"'")
}

fn format_timeout(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis == 0 {
        "1s".to_string()
    } else if millis.is_multiple_of(1000) {
        format!("{}s", millis / 1000)
    } else {
        format!("{:.3}s", millis as f64 / 1000.0)
    }
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

fn strip_known_extension(path: &Path) -> PathBuf {
    let text = path_string(path);
    if let Some(stripped) = text.strip_suffix(".txt") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
