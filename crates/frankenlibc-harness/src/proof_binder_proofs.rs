//! Proof-binder verification and regression gate.
//!
//! Bead: `bd-34s.5`
//!
//! Scope:
//! - Run the canonical Python proof-binder validator against the checked-in binder.
//! - Run the validator's unit-test pack.
//! - Compare the freshly generated validator snapshot with the checked-in
//!   proof-traceability snapshot to catch silent drift.

use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const BEAD_ID: &str = "bd-34s.5";
const GATE: &str = "proof_binder_proofs";
const RUN_ID: &str = "proof-binder-proofs";

#[derive(Debug, Serialize)]
pub struct ProofBinderProofSummary {
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct ProofBinderCommandReport {
    pub ok: bool,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

#[derive(Debug, Serialize)]
pub struct ProofBinderSnapshotSummary {
    pub binder_valid: bool,
    pub total_obligations: usize,
    pub valid_obligations: usize,
    pub invalid_obligations: usize,
    pub total_violations: usize,
    pub categories_covered: Vec<String>,
    pub obligation_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProofBinderRegressionReport {
    pub baseline_matches: bool,
    pub summary_differences: Vec<String>,
    pub missing_categories: Vec<String>,
    pub extra_categories: Vec<String>,
    pub missing_obligations: Vec<String>,
    pub extra_obligations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProofBinderProofSources {
    pub binder_json: String,
    pub baseline_snapshot_json: String,
    pub validator_script: String,
    pub validator_python_tests: String,
    pub log_path: String,
    pub report_path: String,
    pub validator_report_path: String,
}

#[derive(Debug, Serialize)]
pub struct ProofBinderProofReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: ProofBinderProofSources,
    pub summary: ProofBinderProofSummary,
    pub validator: ProofBinderCommandReport,
    pub python_tests: ProofBinderCommandReport,
    pub current_snapshot: ProofBinderSnapshotSummary,
    pub baseline_snapshot: ProofBinderSnapshotSummary,
    pub regression: ProofBinderRegressionReport,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
    validator_report_path: &Path,
) -> Result<ProofBinderProofReport, Box<dyn std::error::Error>> {
    let binder_path = workspace_root.join("tests/conformance/proof_obligations_binder.v1.json");
    let baseline_path = workspace_root.join("tests/conformance/proof_traceability_check.json");
    let validator_script = workspace_root.join("scripts/gentoo/proof_binder_validator.py");
    let python_test_path = workspace_root.join("tests/gentoo/test_proof_binder.py");

    std::fs::create_dir_all(
        log_path
            .parent()
            .ok_or_else(|| std::io::Error::other("log_path must have a parent directory"))?,
    )?;
    std::fs::create_dir_all(
        report_path
            .parent()
            .ok_or_else(|| std::io::Error::other("report_path must have a parent directory"))?,
    )?;
    std::fs::create_dir_all(validator_report_path.parent().ok_or_else(|| {
        std::io::Error::other("validator_report_path must have a parent directory")
    })?)?;

    let artifact_refs = vec![
        rel_path(workspace_root, &binder_path),
        rel_path(workspace_root, &baseline_path),
        rel_path(workspace_root, &validator_script),
        rel_path(workspace_root, &python_test_path),
        rel_path(workspace_root, log_path),
        rel_path(workspace_root, report_path),
        rel_path(workspace_root, validator_report_path),
    ];

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Warn, "proof_binder.scope_boundary")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_api("proof_binder", "scope")
            .with_outcome(Outcome::Pass)
            .with_decision_path("proof->binder->scope_boundary")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "assumption": "the gate validates the checked-in proof binder, unit-test pack, and traceability snapshot parity",
                "non_claim": "it does not prove Lean/Coq/Kani artifacts that are not yet represented in the checked-in binder",
            })),
    )?;

    let validator = run_command(
        workspace_root,
        "python3",
        &[
            validator_script.to_string_lossy().as_ref(),
            "--binder",
            binder_path.to_string_lossy().as_ref(),
            "--dry-run",
            "--format",
            "json",
            "--no-hashes",
            "--output",
            validator_report_path.to_string_lossy().as_ref(),
        ],
    )?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_binder.validator")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_api("proof_binder", "validator")
            .with_outcome(if validator.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_exit_code(validator.exit_code)
            .with_duration_ms(validator.duration_ms)
            .with_decision_path("proof->binder->validator")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "stdout_tail": validator.stdout_tail.clone(),
                "stderr_tail": validator.stderr_tail.clone(),
            })),
    )?;
    if !validator.ok {
        return Err(std::io::Error::other(format!(
            "proof binder validator failed with exit code {}",
            validator.exit_code
        ))
        .into());
    }

    let python_tests = run_command(
        workspace_root,
        "python3",
        &[
            "-m",
            "pytest",
            python_test_path.to_string_lossy().as_ref(),
            "-q",
            "--tb=short",
        ],
    )?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_binder.python_tests")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_api("proof_binder", "pytest")
            .with_outcome(if python_tests.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_exit_code(python_tests.exit_code)
            .with_duration_ms(python_tests.duration_ms)
            .with_decision_path("proof->binder->python_tests")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "stdout_tail": python_tests.stdout_tail.clone(),
                "stderr_tail": python_tests.stderr_tail.clone(),
            })),
    )?;
    if !python_tests.ok {
        return Err(std::io::Error::other(format!(
            "proof binder python tests failed with exit code {}",
            python_tests.exit_code
        ))
        .into());
    }

    let current_value = load_json(validator_report_path)?;
    let baseline_value = load_json(&baseline_path)?;
    let current_snapshot = extract_snapshot_summary(&current_value)?;
    let baseline_snapshot = extract_snapshot_summary(&baseline_value)?;
    let regression = compare_snapshots(&current_snapshot, &baseline_snapshot);

    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_binder.snapshot_regression")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_api("proof_binder", "snapshot_regression")
            .with_outcome(if regression.baseline_matches {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_decision_path("proof->binder->snapshot_regression")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "current_total_obligations": current_snapshot.total_obligations,
                "baseline_total_obligations": baseline_snapshot.total_obligations,
                "summary_differences": regression.summary_differences.clone(),
                "missing_categories": regression.missing_categories.clone(),
                "extra_categories": regression.extra_categories.clone(),
                "missing_obligations": regression.missing_obligations.clone(),
                "extra_obligations": regression.extra_obligations.clone(),
            })),
    )?;

    let mut passed = 0usize;
    let mut failed = 0usize;
    for ok in [
        validator.ok,
        python_tests.ok,
        current_snapshot.binder_valid,
        regression.baseline_matches,
    ] {
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_binder.summary")
            .with_stream(StreamKind::Unit)
            .with_gate(GATE)
            .with_api("proof_binder", "summary")
            .with_outcome(if failed == 0 {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_decision_path("proof->binder->summary")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "checks": 4,
                "passed": passed,
                "failed": failed,
                "binder_valid": current_snapshot.binder_valid,
                "baseline_matches": regression.baseline_matches,
            })),
    )?;
    emitter.flush()?;

    let report = ProofBinderProofReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: LogEntry::new("", LogLevel::Info, "generated").timestamp,
        sources: ProofBinderProofSources {
            binder_json: rel_path(workspace_root, &binder_path),
            baseline_snapshot_json: rel_path(workspace_root, &baseline_path),
            validator_script: rel_path(workspace_root, &validator_script),
            validator_python_tests: rel_path(workspace_root, &python_test_path),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
            validator_report_path: rel_path(workspace_root, validator_report_path),
        },
        summary: ProofBinderProofSummary {
            checks: 4,
            passed,
            failed,
        },
        validator,
        python_tests,
        current_snapshot,
        baseline_snapshot,
        regression,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    if report.summary.failed != 0 {
        return Err(std::io::Error::other(format!(
            "proof binder proofs failed {} check(s)",
            report.summary.failed
        ))
        .into());
    }
    Ok(report)
}

fn run_command(
    workspace_root: &Path,
    program: &str,
    args: &[&str],
) -> Result<ProofBinderCommandReport, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let output = Command::new(program)
        .current_dir(workspace_root)
        .args(args)
        .output()?;
    let duration_ms = start.elapsed().as_millis() as u64;
    Ok(ProofBinderCommandReport {
        ok: output.status.success(),
        exit_code: output.status.code().unwrap_or(-1),
        duration_ms,
        stdout_tail: trim_output_tail(&String::from_utf8_lossy(&output.stdout)),
        stderr_tail: trim_output_tail(&String::from_utf8_lossy(&output.stderr)),
    })
}

fn load_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let body = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}

fn extract_snapshot_summary(
    value: &Value,
) -> Result<ProofBinderSnapshotSummary, Box<dyn std::error::Error>> {
    let categories = value["categories_covered"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("categories_covered must be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| std::io::Error::other("category entry must be a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let obligations = value["obligations"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("obligations must be an array"))?;
    let obligation_ids = obligations
        .iter()
        .map(|entry| {
            entry["obligation_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| std::io::Error::other("obligation_id must be a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ProofBinderSnapshotSummary {
        binder_valid: value["binder_valid"]
            .as_bool()
            .ok_or_else(|| std::io::Error::other("binder_valid must be a bool"))?,
        total_obligations: value["total_obligations"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("total_obligations must be an integer"))?
            as usize,
        valid_obligations: value["valid_obligations"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("valid_obligations must be an integer"))?
            as usize,
        invalid_obligations: value["invalid_obligations"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("invalid_obligations must be an integer"))?
            as usize,
        total_violations: value["total_violations"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("total_violations must be an integer"))?
            as usize,
        categories_covered: categories,
        obligation_ids,
    })
}

fn compare_snapshots(
    current: &ProofBinderSnapshotSummary,
    baseline: &ProofBinderSnapshotSummary,
) -> ProofBinderRegressionReport {
    let mut summary_differences = Vec::new();
    for (label, lhs, rhs) in [
        (
            "binder_valid",
            usize::from(current.binder_valid),
            usize::from(baseline.binder_valid),
        ),
        (
            "total_obligations",
            current.total_obligations,
            baseline.total_obligations,
        ),
        (
            "valid_obligations",
            current.valid_obligations,
            baseline.valid_obligations,
        ),
        (
            "invalid_obligations",
            current.invalid_obligations,
            baseline.invalid_obligations,
        ),
        (
            "total_violations",
            current.total_violations,
            baseline.total_violations,
        ),
    ] {
        if lhs != rhs {
            summary_differences.push(format!("{label}: current={lhs} baseline={rhs}"));
        }
    }

    let missing_categories = baseline
        .categories_covered
        .iter()
        .filter(|category| !current.categories_covered.contains(category))
        .cloned()
        .collect::<Vec<_>>();
    let extra_categories = current
        .categories_covered
        .iter()
        .filter(|category| !baseline.categories_covered.contains(category))
        .cloned()
        .collect::<Vec<_>>();
    let missing_obligations = baseline
        .obligation_ids
        .iter()
        .filter(|obligation| !current.obligation_ids.contains(obligation))
        .cloned()
        .collect::<Vec<_>>();
    let extra_obligations = current
        .obligation_ids
        .iter()
        .filter(|obligation| !baseline.obligation_ids.contains(obligation))
        .cloned()
        .collect::<Vec<_>>();

    let baseline_matches = summary_differences.is_empty()
        && missing_categories.is_empty()
        && extra_categories.is_empty()
        && missing_obligations.is_empty()
        && extra_obligations.is_empty();

    ProofBinderRegressionReport {
        baseline_matches,
        summary_differences,
        missing_categories,
        extra_categories,
        missing_obligations,
        extra_obligations,
    }
}

fn trim_output_tail(output: &str) -> String {
    const MAX_LINES: usize = 10;
    const MAX_CHARS: usize = 1_200;

    let mut lines = output.lines().rev().take(MAX_LINES).collect::<Vec<_>>();
    lines.reverse();
    let mut joined = lines.join("\n");
    if joined.chars().count() > MAX_CHARS {
        let truncated = joined.chars().rev().take(MAX_CHARS).collect::<Vec<_>>();
        joined = truncated.into_iter().rev().collect::<String>();
    }
    joined
}

fn rel_path(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .display()
        .to_string()
}
