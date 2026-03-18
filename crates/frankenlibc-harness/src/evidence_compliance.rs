//! Evidence compliance gate helpers.
//!
//! This module implements the "closure requires hard failure when telemetry is incomplete"
//! rule by validating:
//! - JSONL structured logs conform to `structured_log::validate_log_line`
//! - Artifact index schema and content
//! - Failure-path artifact references resolve to real files and match the index
//!
//! This is build/test tooling only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::structured_log::{
    ArtifactIndex, LogEmitter, LogEntry, LogLevel, Outcome, StreamKind, validate_log_line,
};

const PROOF_BEAD_ID: &str = "bd-34s.7";
const PROOF_GATE: &str = "evidence_compliance";
const PROOF_RUN_ID: &str = "evidence-compliance";
const PROOF_LOG_FILENAME: &str = "evidence_compliance.proof.log.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceViolation {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceComplianceReport {
    pub ok: bool,
    pub violations: Vec<EvidenceViolation>,
}

impl EvidenceComplianceReport {
    #[must_use]
    pub fn ok() -> Self {
        Self {
            ok: true,
            violations: Vec::new(),
        }
    }

    pub fn push(&mut self, v: EvidenceViolation) {
        self.ok = false;
        self.violations.push(v);
    }

    pub fn sort_deterministically(&mut self) {
        self.violations.sort_by(|a, b| {
            a.code
                .cmp(&b.code)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.line_number.cmp(&b.line_number))
                .then_with(|| a.trace_id.cmp(&b.trace_id))
                .then_with(|| a.message.cmp(&b.message))
        });
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing to String should not fail");
    }
    out
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    use sha2::Digest;
    let data =
        std::fs::read(path).map_err(|err| format!("failed reading '{}': {err}", path.display()))?;
    Ok(hex_lower(&sha2::Sha256::digest(&data)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactResolutionSource {
    Absolute,
    RunRoot,
    WorkspaceRoot,
}

fn emit_proof_log(emitter: &mut Option<LogEmitter>, entry: LogEntry) {
    if let Some(emitter) = emitter.as_mut() {
        let _ = emitter.emit_entry(entry);
    }
}

fn resolve_artifact_path(
    workspace_root: &Path,
    run_root: &Path,
    path: &str,
) -> Option<(PathBuf, ArtifactResolutionSource)> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Some((candidate.to_path_buf(), ArtifactResolutionSource::Absolute));
    }

    // Preferred: relative to the run directory (self-contained bundles).
    let in_run = run_root.join(candidate);
    if in_run.exists() {
        return Some((in_run, ArtifactResolutionSource::RunRoot));
    }

    // Fallback: relative to workspace root (legacy scripts).
    let in_ws = workspace_root.join(candidate);
    if in_ws.exists() {
        return Some((in_ws, ArtifactResolutionSource::WorkspaceRoot));
    }

    None
}

fn validate_artifact_join_keys(
    report: &mut EvidenceComplianceReport,
    art_path: &str,
    emitter: &mut Option<LogEmitter>,
    join_keys: &crate::structured_log::ArtifactJoinKeys,
) {
    if join_keys.is_empty() {
        report.push(EvidenceViolation {
            code: "artifact_index.join_keys.empty".to_string(),
            message: format!("artifact '{art_path}' has empty join_keys object"),
            trace_id: None,
            line_number: None,
            path: Some(art_path.to_string()),
            remediation_hint: Some(
                "either omit join_keys entirely or include at least one correlation key"
                    .to_string(),
            ),
        });
    }

    for trace_id in &join_keys.trace_ids {
        if !trace_id.contains("::") {
            report.push(EvidenceViolation {
                code: "artifact_index.join_keys.bad_trace_id".to_string(),
                message: format!("artifact '{art_path}' has malformed trace_id '{trace_id}'"),
                trace_id: Some(trace_id.clone()),
                line_number: None,
                path: Some(art_path.to_string()),
                remediation_hint: Some(
                    "trace_ids must follow the canonical <bead>::<run>::<seq> shape".to_string(),
                ),
            });
        }
    }

    if join_keys.decision_ids.contains(&0) {
        report.push(EvidenceViolation {
            code: "artifact_index.join_keys.bad_decision_id".to_string(),
            message: format!("artifact '{art_path}' includes decision_id=0"),
            trace_id: None,
            line_number: None,
            path: Some(art_path.to_string()),
            remediation_hint: Some("decision_ids must be non-zero when present".to_string()),
        });
    }

    if join_keys.policy_ids.contains(&0) {
        report.push(EvidenceViolation {
            code: "artifact_index.join_keys.bad_policy_id".to_string(),
            message: format!("artifact '{art_path}' includes policy_id=0"),
            trace_id: None,
            line_number: None,
            path: Some(art_path.to_string()),
            remediation_hint: Some("policy_ids must be non-zero when present".to_string()),
        });
    }

    emit_proof_log(
        emitter,
        LogEntry::new(
            "",
            LogLevel::Debug,
            "evidence_compliance.artifact_join_keys",
        )
        .with_stream(StreamKind::Release)
        .with_gate(PROOF_GATE)
        .with_outcome(Outcome::Pass)
        .with_controller_id("artifact_index")
        .with_artifacts(vec![art_path.to_string()])
        .with_details(serde_json::json!({
            "path": art_path,
            "trace_id_count": join_keys.trace_ids.len(),
            "span_id_count": join_keys.span_ids.len(),
            "decision_id_count": join_keys.decision_ids.len(),
            "policy_id_count": join_keys.policy_ids.len(),
            "evidence_seqno_count": join_keys.evidence_seqnos.len(),
            "decision_path": "proof->artifact_integrity->join_keys",
        })),
    );
}

fn validate_artifact_index(
    report: &mut EvidenceComplianceReport,
    workspace_root: &Path,
    index_path: &Path,
    emitter: &mut Option<LogEmitter>,
) -> Option<ArtifactIndex> {
    let run_root = index_path.parent().unwrap_or(workspace_root);
    emit_proof_log(
        emitter,
        LogEntry::new(
            "",
            LogLevel::Info,
            "evidence_compliance.artifact_index_load",
        )
        .with_stream(StreamKind::Release)
        .with_gate(PROOF_GATE)
        .with_outcome(Outcome::Pass)
        .with_controller_id("artifact_index")
        .with_artifacts(vec![index_path.display().to_string()])
        .with_details(serde_json::json!({
            "path": index_path.display().to_string(),
            "decision_path": "proof->artifact_integrity->load_index",
        })),
    );

    let content = match std::fs::read_to_string(index_path) {
        Ok(s) => s,
        Err(err) => {
            report.push(EvidenceViolation {
                code: "artifact_index.missing".to_string(),
                message: format!(
                    "artifact index not readable: {}: {err}",
                    index_path.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(index_path.display().to_string()),
                remediation_hint: Some("regenerate artifact index for the run".to_string()),
            });
            emit_proof_log(
                emitter,
                LogEntry::new(
                    "",
                    LogLevel::Error,
                    "evidence_compliance.artifact_index_missing",
                )
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Fail)
                .with_controller_id("artifact_index")
                .with_artifacts(vec![index_path.display().to_string()])
                .with_details(serde_json::json!({
                    "error": err.to_string(),
                    "decision_path": "proof->artifact_integrity->load_index",
                })),
            );
            return None;
        }
    };

    let idx: ArtifactIndex = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(err) => {
            report.push(EvidenceViolation {
                code: "artifact_index.invalid_json".to_string(),
                message: format!(
                    "artifact index JSON parse failed: {}: {err}",
                    index_path.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(index_path.display().to_string()),
                remediation_hint: Some(
                    "write valid JSON matching the artifact_index schema".to_string(),
                ),
            });
            emit_proof_log(
                emitter,
                LogEntry::new(
                    "",
                    LogLevel::Error,
                    "evidence_compliance.artifact_index_invalid_json",
                )
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Fail)
                .with_controller_id("artifact_index")
                .with_artifacts(vec![index_path.display().to_string()])
                .with_details(serde_json::json!({
                    "error": err.to_string(),
                    "decision_path": "proof->artifact_integrity->parse_index",
                })),
            );
            return None;
        }
    };

    emit_proof_log(
        emitter,
        LogEntry::new(
            "",
            LogLevel::Info,
            "evidence_compliance.artifact_index_loaded",
        )
        .with_stream(StreamKind::Release)
        .with_gate(PROOF_GATE)
        .with_outcome(Outcome::Pass)
        .with_controller_id("artifact_index")
        .with_artifacts(vec![index_path.display().to_string()])
        .with_details(serde_json::json!({
            "index_version": idx.index_version,
            "artifact_count": idx.artifacts.len(),
            "decision_path": "proof->artifact_integrity->parse_index",
        })),
    );

    if idx.index_version != 1 {
        report.push(EvidenceViolation {
            code: "artifact_index.bad_version".to_string(),
            message: format!(
                "artifact index_version must be 1, got {}",
                idx.index_version
            ),
            trace_id: None,
            line_number: None,
            path: Some(index_path.display().to_string()),
            remediation_hint: Some("regenerate artifact index using the v1 schema".to_string()),
        });
        emit_proof_log(
            emitter,
            LogEntry::new(
                "",
                LogLevel::Error,
                "evidence_compliance.artifact_index_bad_version",
            )
            .with_stream(StreamKind::Release)
            .with_gate(PROOF_GATE)
            .with_outcome(Outcome::Fail)
            .with_controller_id("artifact_index")
            .with_artifacts(vec![index_path.display().to_string()])
            .with_details(serde_json::json!({
                "index_version": idx.index_version,
                "decision_path": "proof->artifact_integrity->version_check",
            })),
        );
    }

    for art in &idx.artifacts {
        if let Some(join_keys) = &art.join_keys {
            validate_artifact_join_keys(report, &art.path, emitter, join_keys);
        }

        let resolved = resolve_artifact_path(workspace_root, run_root, &art.path);
        let Some((resolved_path, resolution_source)) = resolved else {
            report.push(EvidenceViolation {
                code: "artifact_index.artifact_missing".to_string(),
                message: format!(
                    "artifact listed in index does not exist: '{}' (searched under '{}' and '{}')",
                    art.path,
                    run_root.display(),
                    workspace_root.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(art.path.clone()),
                remediation_hint: Some(
                    "ensure artifacts are written and paths in artifact_index.json are correct"
                        .to_string(),
                ),
            });
            emit_proof_log(
                emitter,
                LogEntry::new("", LogLevel::Error, "evidence_compliance.artifact_missing")
                    .with_stream(StreamKind::Release)
                    .with_gate(PROOF_GATE)
                    .with_outcome(Outcome::Fail)
                    .with_controller_id("artifact_integrity")
                    .with_artifacts(vec![art.path.clone()])
                    .with_details(serde_json::json!({
                        "path": art.path,
                        "searched_run_root": run_root.display().to_string(),
                        "searched_workspace_root": workspace_root.display().to_string(),
                        "decision_path": "proof->artifact_integrity->resolve_path",
                    })),
            );
            continue;
        };

        if resolution_source == ArtifactResolutionSource::WorkspaceRoot {
            emit_proof_log(
                emitter,
                LogEntry::new("", LogLevel::Warn, "evidence_compliance.artifact_path_fallback")
                    .with_stream(StreamKind::Release)
                    .with_gate(PROOF_GATE)
                    .with_outcome(Outcome::Pass)
                    .with_controller_id("artifact_integrity")
                    .with_artifacts(vec![art.path.clone()])
                    .with_details(serde_json::json!({
                        "path": art.path,
                        "resolved_path": resolved_path.display().to_string(),
                        "assumption": "workspace-root fallback remains equivalent to run-root artifact resolution",
                        "decision_path": "proof->artifact_integrity->resolve_path_fallback",
                    })),
            );
        }

        emit_proof_log(
            emitter,
            LogEntry::new(
                "",
                LogLevel::Debug,
                "evidence_compliance.artifact_hash_compute",
            )
            .with_stream(StreamKind::Release)
            .with_gate(PROOF_GATE)
            .with_outcome(Outcome::Pass)
            .with_controller_id("artifact_integrity")
            .with_artifacts(vec![art.path.clone()])
            .with_details(serde_json::json!({
                "path": art.path,
                "resolved_path": resolved_path.display().to_string(),
                "expected_sha256": art.sha256,
                "decision_path": "proof->artifact_integrity->hash_compute",
            })),
        );

        match sha256_hex(&resolved_path) {
            Ok(actual) => {
                if !actual.eq_ignore_ascii_case(&art.sha256) {
                    report.push(EvidenceViolation {
                        code: "artifact_index.sha_mismatch".to_string(),
                        message: format!(
                            "sha256 mismatch for '{}': expected={}, actual={}",
                            art.path, art.sha256, actual
                        ),
                        trace_id: None,
                        line_number: None,
                        path: Some(art.path.clone()),
                        remediation_hint: Some(
                            "regenerate the artifact or update its sha256 in artifact_index.json"
                                .to_string(),
                        ),
                    });
                    emit_proof_log(
                        emitter,
                        LogEntry::new(
                            "",
                            LogLevel::Error,
                            "evidence_compliance.artifact_hash_mismatch",
                        )
                        .with_stream(StreamKind::Release)
                        .with_gate(PROOF_GATE)
                        .with_outcome(Outcome::Fail)
                        .with_controller_id("artifact_integrity")
                        .with_artifacts(vec![art.path.clone()])
                        .with_details(serde_json::json!({
                            "path": art.path,
                            "expected_sha256": art.sha256,
                            "actual_sha256": actual,
                            "decision_path": "proof->artifact_integrity->hash_verify",
                        })),
                    );
                } else {
                    emit_proof_log(
                        emitter,
                        LogEntry::new(
                            "",
                            LogLevel::Debug,
                            "evidence_compliance.artifact_hash_verified",
                        )
                        .with_stream(StreamKind::Release)
                        .with_gate(PROOF_GATE)
                        .with_outcome(Outcome::Pass)
                        .with_controller_id("artifact_integrity")
                        .with_artifacts(vec![art.path.clone()])
                        .with_details(serde_json::json!({
                            "path": art.path,
                            "actual_sha256": actual,
                            "decision_path": "proof->artifact_integrity->hash_verify",
                        })),
                    );
                }
            }
            Err(err) => {
                report.push(EvidenceViolation {
                    code: "artifact_index.sha_error".to_string(),
                    message: err.clone(),
                    trace_id: None,
                    line_number: None,
                    path: Some(art.path.clone()),
                    remediation_hint: Some("ensure artifact file is readable".to_string()),
                });
                emit_proof_log(
                    emitter,
                    LogEntry::new(
                        "",
                        LogLevel::Error,
                        "evidence_compliance.artifact_hash_error",
                    )
                    .with_stream(StreamKind::Release)
                    .with_gate(PROOF_GATE)
                    .with_outcome(Outcome::Error)
                    .with_controller_id("artifact_integrity")
                    .with_artifacts(vec![art.path.clone()])
                    .with_details(serde_json::json!({
                        "path": art.path,
                        "error": err,
                        "decision_path": "proof->artifact_integrity->hash_compute",
                    })),
                );
            }
        }
    }

    Some(idx)
}

fn validate_failure_artifact_refs(
    report: &mut EvidenceComplianceReport,
    workspace_root: &Path,
    run_root: &Path,
    idx: &ArtifactIndex,
    emitter: &mut Option<LogEmitter>,
    trace_id: Option<String>,
    refs: &[String],
) {
    for r in refs {
        let resolved = resolve_artifact_path(workspace_root, run_root, r);
        if let Some((resolved_path, ArtifactResolutionSource::WorkspaceRoot)) = &resolved {
            emit_proof_log(
                emitter,
                LogEntry::new("", LogLevel::Warn, "evidence_compliance.artifact_path_fallback")
                    .with_stream(StreamKind::Release)
                    .with_gate(PROOF_GATE)
                    .with_outcome(Outcome::Pass)
                    .with_controller_id("failure_artifacts")
                    .with_artifacts(vec![r.clone()])
                    .with_details(serde_json::json!({
                        "path": r,
                        "resolved_path": resolved_path.display().to_string(),
                        "assumption": "workspace-root fallback remains equivalent for failure artifact refs",
                        "decision_path": "proof->failure_artifacts->resolve_path_fallback",
                    })),
            );
        }
        if resolved.is_none() {
            report.push(EvidenceViolation {
                code: "failure_artifact_ref.missing".to_string(),
                message: format!(
                    "failure artifact ref does not exist: '{r}' (searched under '{}' and '{}')",
                    run_root.display(),
                    workspace_root.display()
                ),
                trace_id: trace_id.clone(),
                line_number: None,
                path: Some(r.clone()),
                remediation_hint: Some("write the referenced diagnostic artifact".to_string()),
            });
            emit_proof_log(
                emitter,
                LogEntry::new(
                    "",
                    LogLevel::Error,
                    "evidence_compliance.failure_artifact_missing",
                )
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Fail)
                .with_controller_id("failure_artifacts")
                .with_artifacts(vec![r.clone()])
                .with_details(serde_json::json!({
                    "trace_id": trace_id.clone(),
                    "path": r,
                    "searched_run_root": run_root.display().to_string(),
                    "searched_workspace_root": workspace_root.display().to_string(),
                    "decision_path": "proof->failure_artifacts->resolve_path",
                })),
            );
        }

        if !idx.artifacts.iter().any(|a| a.path == *r) {
            report.push(EvidenceViolation {
                code: "failure_artifact_ref.not_indexed".to_string(),
                message: format!("failure artifact ref not present in artifact_index.json: '{r}'"),
                trace_id: trace_id.clone(),
                line_number: None,
                path: Some(r.clone()),
                remediation_hint: Some(
                    "add the artifact to artifact_index.json (path/kind/sha256)".to_string(),
                ),
            });
            emit_proof_log(
                emitter,
                LogEntry::new(
                    "",
                    LogLevel::Error,
                    "evidence_compliance.failure_artifact_not_indexed",
                )
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Fail)
                .with_controller_id("failure_artifacts")
                .with_artifacts(vec![r.clone()])
                .with_details(serde_json::json!({
                    "trace_id": trace_id.clone(),
                    "path": r,
                    "decision_path": "proof->failure_artifacts->index_membership",
                })),
            );
        }
    }
}

/// Validate a (log, index) evidence bundle.
///
/// `workspace_root` is used as a fallback for legacy artifact paths; `index_path.parent()`
/// is treated as the preferred run root.
#[must_use]
pub fn validate_evidence_bundle(
    workspace_root: &Path,
    log_path: &Path,
    index_path: &Path,
) -> EvidenceComplianceReport {
    let mut report = EvidenceComplianceReport::ok();
    let run_root = index_path.parent().unwrap_or(workspace_root);
    let proof_log_path = run_root.join(PROOF_LOG_FILENAME);

    let mut emitter = match LogEmitter::to_file(&proof_log_path, PROOF_BEAD_ID, PROOF_RUN_ID) {
        Ok(emitter) => Some(emitter),
        Err(err) => {
            report.push(EvidenceViolation {
                code: "proof_log.unwritable".to_string(),
                message: format!(
                    "proof log not writable: {}: {err}",
                    proof_log_path.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(proof_log_path.display().to_string()),
                remediation_hint: Some(
                    "ensure parent directory exists and is writable for proof logs".to_string(),
                ),
            });
            None
        }
    };

    emit_proof_log(
        &mut emitter,
        LogEntry::new("", LogLevel::Info, "evidence_compliance.proof_start")
            .with_stream(StreamKind::Release)
            .with_gate(PROOF_GATE)
            .with_outcome(Outcome::Pass)
            .with_controller_id("evidence_compliance")
            .with_artifacts(vec![
                log_path.display().to_string(),
                index_path.display().to_string(),
            ])
            .with_details(serde_json::json!({
                "workspace_root": workspace_root.display().to_string(),
                "decision_path": "proof->evidence_compliance->start",
            })),
    );

    let idx = match validate_artifact_index(&mut report, workspace_root, index_path, &mut emitter) {
        Some(v) => v,
        None => {
            report.sort_deterministically();
            emit_proof_log(
                &mut emitter,
                LogEntry::new("", LogLevel::Error, "evidence_compliance.proof_failure")
                    .with_stream(StreamKind::Release)
                    .with_gate(PROOF_GATE)
                    .with_outcome(Outcome::Fail)
                    .with_controller_id("evidence_compliance")
                    .with_artifacts(vec![proof_log_path.display().to_string()])
                    .with_details(serde_json::json!({
                        "violation_count": report.violations.len(),
                        "decision_path": "proof->evidence_compliance->artifact_index",
                    })),
            );
            if let Some(emitter) = emitter.as_mut() {
                let _ = emitter.flush();
            }
            return report;
        }
    };

    let content = match std::fs::read_to_string(log_path) {
        Ok(s) => s,
        Err(err) => {
            report.push(EvidenceViolation {
                code: "log.missing".to_string(),
                message: format!("log not readable: {}: {err}", log_path.display()),
                trace_id: None,
                line_number: None,
                path: Some(log_path.display().to_string()),
                remediation_hint: Some("ensure the run writes a JSONL log file".to_string()),
            });
            emit_proof_log(
                &mut emitter,
                LogEntry::new("", LogLevel::Error, "evidence_compliance.log_missing")
                    .with_stream(StreamKind::Release)
                    .with_gate(PROOF_GATE)
                    .with_outcome(Outcome::Fail)
                    .with_controller_id("structured_log")
                    .with_artifacts(vec![log_path.display().to_string()])
                    .with_details(serde_json::json!({
                        "error": err.to_string(),
                        "decision_path": "proof->evidence_compliance->load_log",
                    })),
            );
            report.sort_deterministically();
            if let Some(emitter) = emitter.as_mut() {
                let _ = emitter.flush();
            }
            return report;
        }
    };

    for (idx_line, raw) in content.lines().enumerate() {
        let line_no = idx_line + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        let entry = match validate_log_line(line, line_no) {
            Ok(e) => e,
            Err(errs) => {
                for e in errs {
                    let message = e.message.clone();
                    report.push(EvidenceViolation {
                        code: "log.schema_violation".to_string(),
                        message: message.clone(),
                        trace_id: None,
                        line_number: Some(e.line_number),
                        path: Some(log_path.display().to_string()),
                        remediation_hint: Some(format!(
                            "fix field '{}' in emitted log line",
                            e.field
                        )),
                    });
                    emit_proof_log(
                        &mut emitter,
                        LogEntry::new(
                            "",
                            LogLevel::Error,
                            "evidence_compliance.log_schema_violation",
                        )
                        .with_stream(StreamKind::Release)
                        .with_gate(PROOF_GATE)
                        .with_outcome(Outcome::Fail)
                        .with_controller_id("structured_log")
                        .with_artifacts(vec![log_path.display().to_string()])
                        .with_details(serde_json::json!({
                            "line_number": e.line_number,
                            "message": message,
                            "decision_path": "proof->evidence_compliance->schema_validation",
                        })),
                    );
                }
                continue;
            }
        };

        emit_proof_log(
            &mut emitter,
            LogEntry::new("", LogLevel::Trace, "evidence_compliance.proof_step")
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Pass)
                .with_controller_id("structured_log")
                .with_details(serde_json::json!({
                    "line_number": line_no,
                    "trace_id": entry.trace_id.clone(),
                    "event": entry.event.clone(),
                    "decision_path": "proof->evidence_compliance->proof_step",
                })),
        );

        let is_failure = matches!(
            entry.outcome,
            Some(Outcome::Fail) | Some(Outcome::Error) | Some(Outcome::Timeout)
        );
        if !is_failure {
            continue;
        }

        let refs = entry.artifact_refs.clone().unwrap_or_default();
        if refs.is_empty() {
            report.push(EvidenceViolation {
                code: "failure_event.missing_artifact_refs".to_string(),
                message: "failure outcome requires non-empty artifact_refs".to_string(),
                trace_id: Some(entry.trace_id.clone()),
                line_number: Some(line_no),
                path: Some(log_path.display().to_string()),
                remediation_hint: Some(
                    "emit artifact_refs pointing to diffs/backtraces/reports for the failure"
                        .to_string(),
                ),
            });
            emit_proof_log(
                &mut emitter,
                LogEntry::new(
                    "",
                    LogLevel::Error,
                    "evidence_compliance.failure_event_missing_artifact_refs",
                )
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Fail)
                .with_controller_id("failure_artifacts")
                .with_artifacts(vec![log_path.display().to_string()])
                .with_details(serde_json::json!({
                    "line_number": line_no,
                    "trace_id": entry.trace_id.clone(),
                    "decision_path": "proof->failure_artifacts->required_refs",
                })),
            );
            continue;
        }

        validate_failure_artifact_refs(
            &mut report,
            workspace_root,
            run_root,
            &idx,
            &mut emitter,
            Some(entry.trace_id.clone()),
            &refs,
        );
    }

    report.sort_deterministically();
    emit_proof_log(
        &mut emitter,
        LogEntry::new("", LogLevel::Info, "evidence_compliance.proof_summary")
            .with_stream(StreamKind::Release)
            .with_gate(PROOF_GATE)
            .with_outcome(if report.ok {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_controller_id("evidence_compliance")
            .with_artifacts(vec![proof_log_path.display().to_string()])
            .with_details(serde_json::json!({
                "ok": report.ok,
                "violation_count": report.violations.len(),
                "decision_path": "proof->evidence_compliance->summary",
            })),
    );
    if !report.ok {
        emit_proof_log(
            &mut emitter,
            LogEntry::new("", LogLevel::Error, "evidence_compliance.proof_failure")
                .with_stream(StreamKind::Release)
                .with_gate(PROOF_GATE)
                .with_outcome(Outcome::Fail)
                .with_controller_id("evidence_compliance")
                .with_artifacts(vec![proof_log_path.display().to_string()])
                .with_details(serde_json::json!({
                    "violation_count": report.violations.len(),
                    "decision_path": "proof->evidence_compliance->summary",
                })),
        );
    }
    if let Some(emitter) = emitter.as_mut() {
        let _ = emitter.flush();
    }
    report
}
