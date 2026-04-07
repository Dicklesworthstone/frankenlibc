//! Proof-chain E2E gate for proof-obligation integrity, dashboarding, and
//! cross-report contradiction checks.
//!
//! Bead: `bd-34s.6`

use crate::proof_binder_proofs;
use crate::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const BEAD_ID: &str = "bd-34s.6";
const GATE: &str = "proof_chain_e2e";
const RUN_ID: &str = "proof-chain-e2e";
const PROOF_BINDER_GATE_PATH: &str = "scripts/check_proof_binder.sh";
const PROOF_TRACEABILITY_ARTIFACT: &str = "tests/conformance/proof_traceability_check.json";

#[derive(Debug, Serialize)]
pub struct ProcessReport {
    pub ok: bool,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

#[derive(Debug, Serialize)]
pub struct ProofChainSummary {
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
}

#[derive(Debug, Serialize)]
pub struct ProofBinderStepReport {
    pub ok: bool,
    pub binder_log_path: String,
    pub binder_report_path: String,
    pub validator_report_path: String,
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub total_obligations: usize,
    pub invalid_obligations: usize,
    pub total_violations: usize,
}

#[derive(Debug, Serialize)]
pub struct ChainIntegrityReport {
    pub ok: bool,
    pub checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub duplicate_ids: Vec<String>,
    pub missing_validator_obligations: Vec<String>,
    pub traceability_without_binder_gate: Vec<String>,
    pub docs_without_source_refs: Vec<String>,
    pub self_certifying_in_progress: Vec<String>,
    pub owner_join_key_mismatches: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProofDashboardReport {
    pub ok: bool,
    pub total_obligations: usize,
    pub valid_obligations: usize,
    pub invalid_obligations: usize,
    pub total_violations: usize,
    pub categories_covered: Vec<String>,
    pub status_counts: BTreeMap<String, usize>,
    pub owner_counts: BTreeMap<String, usize>,
    pub gate_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct CrossReportConsistencyReport {
    pub ok: bool,
    pub report_path: String,
    pub command: ProcessReport,
    pub overall_verdict: String,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub error_findings: usize,
    pub warning_findings: usize,
}

#[derive(Debug, Serialize)]
pub struct ProofChainSources {
    pub binder_json: String,
    pub proof_traceability_json: String,
    pub cross_report_generator: String,
    pub log_path: String,
    pub report_path: String,
}

#[derive(Debug, Serialize)]
pub struct ProofChainE2eReport {
    pub schema_version: &'static str,
    pub bead: &'static str,
    pub generated_at: String,
    pub sources: ProofChainSources,
    pub summary: ProofChainSummary,
    pub proof_binder: ProofBinderStepReport,
    pub chain_integrity: ChainIntegrityReport,
    pub dashboard: ProofDashboardReport,
    pub cross_report_consistency: CrossReportConsistencyReport,
}

pub fn run_and_write(
    workspace_root: &Path,
    log_path: &Path,
    report_path: &Path,
    binder_log_path: &Path,
    binder_report_path: &Path,
    validator_report_path: &Path,
    cross_report_path: &Path,
) -> Result<ProofChainE2eReport, Box<dyn std::error::Error>> {
    let binder_path = workspace_root.join("tests/conformance/proof_obligations_binder.v1.json");
    let traceability_path = workspace_root.join(PROOF_TRACEABILITY_ARTIFACT);
    let cross_report_script = workspace_root.join("scripts/generate_cross_report_consistency.py");

    create_parent_dir(log_path)?;
    create_parent_dir(report_path)?;
    create_parent_dir(binder_log_path)?;
    create_parent_dir(binder_report_path)?;
    create_parent_dir(validator_report_path)?;
    create_parent_dir(cross_report_path)?;

    let artifact_refs = vec![
        rel_path(workspace_root, &binder_path),
        rel_path(workspace_root, &traceability_path),
        rel_path(workspace_root, &cross_report_script),
        rel_path(workspace_root, log_path),
        rel_path(workspace_root, report_path),
        rel_path(workspace_root, binder_log_path),
        rel_path(workspace_root, binder_report_path),
        rel_path(workspace_root, validator_report_path),
        rel_path(workspace_root, cross_report_path),
    ];

    let mut emitter = LogEmitter::to_file(log_path, BEAD_ID, RUN_ID)?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Warn, "proof_chain.scope_boundary")
            .with_stream(StreamKind::E2e)
            .with_gate(GATE)
            .with_api("proof_chain", "scope")
            .with_outcome(Outcome::Pass)
            .with_decision_path("proof->chain->scope_boundary")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "assumption": "proof-chain E2E validates proof binder integrity, derived dashboard totals, and contradiction-sensitive report consistency together",
                "non_claim": "it does not claim theorem-level mechanized proof completeness beyond the checked-in proof-obligation binder",
            })),
    )?;

    let proof_binder_report = proof_binder_proofs::run_and_write(
        workspace_root,
        binder_log_path,
        binder_report_path,
        validator_report_path,
    )?;
    let proof_binder = ProofBinderStepReport {
        ok: proof_binder_report.summary.failed == 0,
        binder_log_path: rel_path(workspace_root, binder_log_path),
        binder_report_path: rel_path(workspace_root, binder_report_path),
        validator_report_path: rel_path(workspace_root, validator_report_path),
        checks: proof_binder_report.summary.checks,
        passed: proof_binder_report.summary.passed,
        failed: proof_binder_report.summary.failed,
        total_obligations: proof_binder_report.current_snapshot.total_obligations,
        invalid_obligations: proof_binder_report.current_snapshot.invalid_obligations,
        total_violations: proof_binder_report.current_snapshot.total_violations,
    };
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_chain.proof_binder")
            .with_stream(StreamKind::E2e)
            .with_gate(GATE)
            .with_api("proof_chain", "proof_binder")
            .with_outcome(if proof_binder.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_decision_path("proof->chain->proof_binder")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "checks": proof_binder.checks,
                "failed": proof_binder.failed,
                "total_obligations": proof_binder.total_obligations,
                "invalid_obligations": proof_binder.invalid_obligations,
                "total_violations": proof_binder.total_violations,
            })),
    )?;

    let binder_value = load_json(&binder_path)?;
    let validator_value = load_json(validator_report_path)?;

    let chain_integrity = evaluate_chain_integrity(&binder_value, &validator_value)?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_chain.chain_integrity")
            .with_stream(StreamKind::E2e)
            .with_gate(GATE)
            .with_api("proof_chain", "chain_integrity")
            .with_outcome(if chain_integrity.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_decision_path("proof->chain->integrity")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "checks": chain_integrity.checks,
                "failed": chain_integrity.failed,
                "duplicate_ids": chain_integrity.duplicate_ids,
                "missing_validator_obligations": chain_integrity.missing_validator_obligations,
                "traceability_without_binder_gate": chain_integrity.traceability_without_binder_gate,
                "docs_without_source_refs": chain_integrity.docs_without_source_refs,
                "self_certifying_in_progress": chain_integrity.self_certifying_in_progress,
                "owner_join_key_mismatches": chain_integrity.owner_join_key_mismatches,
            })),
    )?;

    let dashboard = build_dashboard(&binder_value, &validator_value)?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_chain.dashboard")
            .with_stream(StreamKind::E2e)
            .with_gate(GATE)
            .with_api("proof_chain", "dashboard")
            .with_outcome(if dashboard.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_decision_path("proof->chain->dashboard")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "total_obligations": dashboard.total_obligations,
                "invalid_obligations": dashboard.invalid_obligations,
                "total_violations": dashboard.total_violations,
                "status_counts": dashboard.status_counts,
                "owner_counts": dashboard.owner_counts,
                "category_count": dashboard.categories_covered.len(),
            })),
    )?;

    let cross_report_command = run_command(
        workspace_root,
        "python3",
        &[
            cross_report_script.to_string_lossy().as_ref(),
            "--output",
            cross_report_path.to_string_lossy().as_ref(),
        ],
    )?;
    let cross_report =
        summarize_cross_report(workspace_root, cross_report_path, cross_report_command)?;
    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_chain.cross_report_consistency")
            .with_stream(StreamKind::E2e)
            .with_gate(GATE)
            .with_api("proof_chain", "cross_report_consistency")
            .with_outcome(if cross_report.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_exit_code(cross_report.command.exit_code)
            .with_duration_ms(cross_report.command.duration_ms)
            .with_decision_path("proof->chain->cross_report_consistency")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "overall_verdict": cross_report.overall_verdict,
                "critical_findings": cross_report.critical_findings,
                "error_findings": cross_report.error_findings,
                "warning_findings": cross_report.warning_findings,
                "stdout_tail": cross_report.command.stdout_tail,
                "stderr_tail": cross_report.command.stderr_tail,
            })),
    )?;

    let mut passed = 0usize;
    let mut failed = 0usize;
    for ok in [
        proof_binder.ok,
        chain_integrity.ok,
        dashboard.ok,
        cross_report.ok,
    ] {
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    emitter.emit_entry(
        LogEntry::new("", LogLevel::Info, "proof_chain.summary")
            .with_stream(StreamKind::E2e)
            .with_gate(GATE)
            .with_api("proof_chain", "summary")
            .with_outcome(if failed == 0 {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_decision_path("proof->chain->summary")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "checks": 4,
                "passed": passed,
                "failed": failed,
                "total_obligations": dashboard.total_obligations,
                "invalid_obligations": dashboard.invalid_obligations,
                "critical_findings": cross_report.critical_findings,
                "error_findings": cross_report.error_findings,
            })),
    )?;
    emitter.flush()?;

    let report = ProofChainE2eReport {
        schema_version: "v1",
        bead: BEAD_ID,
        generated_at: LogEntry::new("", LogLevel::Info, "generated").timestamp,
        sources: ProofChainSources {
            binder_json: rel_path(workspace_root, &binder_path),
            proof_traceability_json: rel_path(workspace_root, &traceability_path),
            cross_report_generator: rel_path(workspace_root, &cross_report_script),
            log_path: rel_path(workspace_root, log_path),
            report_path: rel_path(workspace_root, report_path),
        },
        summary: ProofChainSummary {
            checks: 4,
            passed,
            failed,
        },
        proof_binder,
        chain_integrity,
        dashboard,
        cross_report_consistency: cross_report,
    };

    std::fs::write(report_path, serde_json::to_string_pretty(&report)?)?;
    if report.summary.failed != 0 {
        return Err(std::io::Error::other(format!(
            "proof chain e2e failed {} check(s)",
            report.summary.failed
        ))
        .into());
    }
    Ok(report)
}

fn evaluate_chain_integrity(
    binder_value: &Value,
    validator_value: &Value,
) -> Result<ChainIntegrityReport, Box<dyn std::error::Error>> {
    let obligations = binder_value["obligations"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("binder obligations must be an array"))?;
    let validator_obligations = validator_value["obligations"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("validator obligations must be an array"))?;

    let mut validator_by_id = BTreeMap::new();
    for entry in validator_obligations {
        let Some(id) = entry["obligation_id"].as_str() else {
            return Err(std::io::Error::other("validator obligation_id must be a string").into());
        };
        validator_by_id.insert(id.to_string(), entry);
    }

    let mut seen_ids = BTreeSet::new();
    let mut duplicate_ids = Vec::new();
    let mut missing_validator_obligations = Vec::new();
    let mut traceability_without_binder_gate = Vec::new();
    let mut docs_without_source_refs = Vec::new();
    let mut self_certifying_in_progress = Vec::new();
    let mut owner_join_key_mismatches = Vec::new();

    for entry in obligations {
        let id = required_string(entry, "id")?;
        if !seen_ids.insert(id.to_string()) {
            duplicate_ids.push(id.to_string());
        }

        let Some(validator_entry) = validator_by_id.get(id) else {
            missing_validator_obligations.push(id.to_string());
            continue;
        };

        let status = required_string(entry, "status")?;
        let owner = required_string(entry, "owner")?;
        let evidence_artifacts = string_array(entry.get("evidence_artifacts"))?;
        let gates = string_array(entry.get("gates"))?;
        let join_keys = string_array(entry.get("join_keys"))?;

        if evidence_artifacts
            .iter()
            .any(|artifact| artifact == PROOF_TRACEABILITY_ARTIFACT)
            && !gates.iter().any(|gate| gate == PROOF_BINDER_GATE_PATH)
        {
            traceability_without_binder_gate.push(id.to_string());
        }

        if evidence_artifacts
            .iter()
            .any(|artifact| artifact.starts_with("docs/proofs/"))
            && validator_entry["source_refs_valid"].as_u64().unwrap_or(0) == 0
        {
            docs_without_source_refs.push(id.to_string());
        }

        if status == "in_progress" {
            if gates
                .iter()
                .filter(|gate| gate.as_str() != PROOF_BINDER_GATE_PATH)
                .count()
                == 0
            {
                self_certifying_in_progress.push(id.to_string());
            }

            let bead_join_keys = join_keys
                .iter()
                .filter_map(|key| key.strip_prefix("bead="))
                .collect::<Vec<_>>();
            if bead_join_keys.len() != 1 || bead_join_keys[0] != owner {
                owner_join_key_mismatches.push(format!(
                    "{id}: owner={owner}, bead_join_keys={}",
                    bead_join_keys.join(",")
                ));
            }
        }
    }

    let failures = [
        duplicate_ids.is_empty(),
        missing_validator_obligations.is_empty(),
        traceability_without_binder_gate.is_empty(),
        docs_without_source_refs.is_empty(),
        self_certifying_in_progress.is_empty(),
        owner_join_key_mismatches.is_empty(),
    ];
    let passed = failures.iter().filter(|ok| **ok).count();
    let failed = failures.len() - passed;

    Ok(ChainIntegrityReport {
        ok: failed == 0,
        checks: failures.len(),
        passed,
        failed,
        duplicate_ids,
        missing_validator_obligations,
        traceability_without_binder_gate,
        docs_without_source_refs,
        self_certifying_in_progress,
        owner_join_key_mismatches,
    })
}

fn build_dashboard(
    binder_value: &Value,
    validator_value: &Value,
) -> Result<ProofDashboardReport, Box<dyn std::error::Error>> {
    let binder_obligations = binder_value["obligations"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("binder obligations must be an array"))?;
    let validator_obligations = validator_value["obligations"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("validator obligations must be an array"))?;

    let mut status_counts = BTreeMap::<String, usize>::new();
    let mut owner_counts = BTreeMap::<String, usize>::new();
    let mut gate_counts = BTreeMap::<String, usize>::new();

    for entry in binder_obligations {
        *status_counts
            .entry(required_string(entry, "status")?.to_string())
            .or_default() += 1;
        *owner_counts
            .entry(required_string(entry, "owner")?.to_string())
            .or_default() += 1;
        for gate in string_array(entry.get("gates"))? {
            *gate_counts.entry(gate).or_default() += 1;
        }
    }

    let categories_covered = validator_value["categories_covered"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("categories_covered must be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| std::io::Error::other("category must be a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let ok = validator_value["binder_valid"].as_bool() == Some(true)
        && validator_value["invalid_obligations"].as_u64().unwrap_or(1) == 0
        && validator_value["total_violations"].as_u64().unwrap_or(1) == 0
        && !validator_obligations.is_empty()
        && !owner_counts.is_empty()
        && !gate_counts.is_empty();

    Ok(ProofDashboardReport {
        ok,
        total_obligations: validator_value["total_obligations"].as_u64().unwrap_or(0) as usize,
        valid_obligations: validator_value["valid_obligations"].as_u64().unwrap_or(0) as usize,
        invalid_obligations: validator_value["invalid_obligations"].as_u64().unwrap_or(0) as usize,
        total_violations: validator_value["total_violations"].as_u64().unwrap_or(0) as usize,
        categories_covered,
        status_counts,
        owner_counts,
        gate_counts,
    })
}

fn summarize_cross_report(
    workspace_root: &Path,
    cross_report_path: &Path,
    command: ProcessReport,
) -> Result<CrossReportConsistencyReport, Box<dyn std::error::Error>> {
    let value = load_json(cross_report_path)?;
    let summary = &value["summary"];
    let critical_findings = summary["by_severity"]["critical"].as_u64().unwrap_or(0) as usize;
    let error_findings = summary["by_severity"]["error"].as_u64().unwrap_or(0) as usize;
    let warning_findings = summary["by_severity"]["warning"].as_u64().unwrap_or(0) as usize;
    let overall_verdict = summary["overall_verdict"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    Ok(CrossReportConsistencyReport {
        ok: command.ok && critical_findings == 0 && error_findings == 0,
        report_path: rel_path(workspace_root, cross_report_path),
        command,
        overall_verdict,
        total_findings: summary["total_findings"].as_u64().unwrap_or(0) as usize,
        critical_findings,
        error_findings,
        warning_findings,
    })
}

fn create_parent_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path must have a parent directory"))?;
    std::fs::create_dir_all(parent)?;
    Ok(())
}

fn run_command(
    workspace_root: &Path,
    program: &str,
    args: &[&str],
) -> Result<ProcessReport, Box<dyn std::error::Error>> {
    let start = Instant::now();
    let output = Command::new(program)
        .current_dir(workspace_root)
        .args(args)
        .output()?;
    let duration_ms = start.elapsed().as_millis() as u64;
    Ok(ProcessReport {
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

fn string_array(value: Option<&Value>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| std::io::Error::other("expected array value"))?;
    entries
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| std::io::Error::other("expected string array entry"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn required_string<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value[field]
        .as_str()
        .ok_or_else(|| std::io::Error::other(format!("{field} must be a string")).into())
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
