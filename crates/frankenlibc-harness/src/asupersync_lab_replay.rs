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

/// Validate a replay record. Fails closed when ANY required field
/// is missing or blank.
pub fn validate_replay(r: &ReplayRecord) -> Result<(), ReplayValidationError> {
    if r.schema_version.is_empty() {
        return Err(ReplayValidationError::MissingSchemaVersion);
    }
    if r.trace_class.is_empty() {
        return Err(ReplayValidationError::MissingTraceClass);
    }
    if r.schedule_decisions.is_empty() {
        return Err(ReplayValidationError::MissingScheduleDecisions);
    }
    if r.replay_inputs.is_empty() {
        return Err(ReplayValidationError::MissingReplayInputs);
    }
    if r.expected_outputs.is_empty() {
        return Err(ReplayValidationError::MissingExpectedOutputs);
    }
    if r.artifact_refs.is_empty() {
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
        validate_replay(&record()).unwrap();
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
    fn validate_rejects_missing_replay_inputs() {
        let mut r = record();
        r.replay_inputs.clear();
        assert_eq!(
            validate_replay(&r),
            Err(ReplayValidationError::MissingReplayInputs)
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
    fn outcome_code_failure_when_observed_diverges_from_expected() {
        let r = record();
        let observed = vec!["target/conformance/stdio_fread_small.divergent.jsonl".to_string()];
        match classify_outcome(&r, true, &observed) {
            ReplayOutcome::CodeFailure { signature } => {
                assert!(signature.starts_with("stdio.fread_small::"));
                assert!(signature.contains("missing="));
                assert!(signature.contains("extra="));
            }
            other => panic!("expected CodeFailure; got {other:?}"),
        }
    }

    #[test]
    fn outcome_tool_failure_when_asupersync_unavailable_even_if_outputs_match() {
        let r = record();
        let outcome = classify_outcome(&r, false, &r.expected_outputs);
        match outcome {
            ReplayOutcome::ToolFailure { reason } => {
                assert!(reason.contains("asupersync tool unavailable"));
                assert!(reason.contains("stdio.fread_small"));
            }
            other => panic!("expected ToolFailure; got {other:?}"),
        }
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
}
