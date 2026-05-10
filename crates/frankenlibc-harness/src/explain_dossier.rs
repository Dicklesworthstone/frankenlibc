//! User-facing explain dossier (bd-juvqm.10).
//!
//! Joins workload-replay metadata, runtime decision evidence,
//! standalone blocker snapshots, L1 dashboard rows, and a
//! semantic-overlay summary into a single compact explanation.
//! The dossier is **derived** from existing evidence — the
//! generator never invents claims and never promotes the support
//! taxonomy ("works on host", "works under preload") into a
//! semantic-parity assertion.
//!
//! Output is deterministic JSON + optional markdown; every claim
//! cites the artifact_refs and source_commit it was joined from.
//!
//! Failure modes (every variant fail-closed):
//!   * Empty artifact_refs on any input row → `MissingArtifactRefs`
//!   * Stale source_commit on any input row → `StaleSourceCommit`
//!   * Missing required input row → `MissingRequiredInput`
//!   * Support-taxonomy claim that names a "passes" status without
//!     a paired semantic-parity artifact_ref →
//!     `SupportTaxonomyPromotedWithoutSemanticParity`

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub artifact_refs: Vec<String>,
    pub source_commit: String,
    /// Free-form summary string distilled from the artifact.
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    WorkloadReplay,
    RuntimeDecisionLog,
    StandaloneBlockerSnapshot,
    L1DashboardRow,
    SemanticOverlay,
}

impl EvidenceKind {
    pub fn label(self) -> &'static str {
        match self {
            EvidenceKind::WorkloadReplay => "workload_replay",
            EvidenceKind::RuntimeDecisionLog => "runtime_decision_log",
            EvidenceKind::StandaloneBlockerSnapshot => "standalone_blocker_snapshot",
            EvidenceKind::L1DashboardRow => "l1_dashboard_row",
            EvidenceKind::SemanticOverlay => "semantic_overlay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DossierEvidencePath {
    pub kind: EvidenceKind,
    pub kind_label: &'static str,
    pub path: &'static str,
    pub summary_pointer: &'static str,
    pub source_commit_pointer: &'static str,
}

/// Canonical on-disk evidence paths for [`load_dossier_inputs_from_disk`].
/// The JSON pointer fields document exactly where each evidence row's
/// `summary` and `source_commit` are read from.
pub const DOSSIER_EVIDENCE_PATHS: [DossierEvidencePath; 5] = [
    DossierEvidencePath {
        kind: EvidenceKind::WorkloadReplay,
        kind_label: "workload_replay",
        path: "target/conformance/workload_replay.log.jsonl",
        summary_pointer: "/summary",
        source_commit_pointer: "/source_commit",
    },
    DossierEvidencePath {
        kind: EvidenceKind::RuntimeDecisionLog,
        kind_label: "runtime_decision_log",
        path: "target/conformance/runtime_decision.log.jsonl",
        summary_pointer: "/summary",
        source_commit_pointer: "/source_commit",
    },
    DossierEvidencePath {
        kind: EvidenceKind::StandaloneBlockerSnapshot,
        kind_label: "standalone_blocker_snapshot",
        path: "tests/conformance/standalone_replacement_artifact.v1.json",
        summary_pointer: "/description",
        source_commit_pointer: "/source_commit",
    },
    DossierEvidencePath {
        kind: EvidenceKind::L1DashboardRow,
        kind_label: "l1_dashboard_row",
        path: "tests/conformance/replacement_level_dashboard.v1.json",
        summary_pointer: "/summary/status",
        source_commit_pointer: "/source_commit",
    },
    DossierEvidencePath {
        kind: EvidenceKind::SemanticOverlay,
        kind_label: "semantic_overlay",
        path: "tests/conformance/semantic_contract_inventory.v1.json",
        summary_pointer: "/summary/blocked_claim",
        source_commit_pointer: "/source_commit",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DossierInputs {
    pub workload_replay: Option<EvidenceRef>,
    pub runtime_decision_log: Option<EvidenceRef>,
    pub standalone_blocker_snapshot: Option<EvidenceRef>,
    pub l1_dashboard_row: Option<EvidenceRef>,
    pub semantic_overlay: Option<EvidenceRef>,
    /// Replacement / interpose level the run reports — drawn from
    /// `standalone_blocker_snapshot` or `l1_dashboard_row`.
    pub replacement_level: String,
    /// First blocker that prevents the run from being declared
    /// passing. Empty string if there is none.
    pub first_failing_blocker: String,
    /// Top N decision-evidence terms from the runtime decision log.
    pub top_decision_terms: Vec<String>,
    /// Strict/hardened divergence signature, if any. Empty when no
    /// divergence is recorded.
    pub strict_hardened_divergence_signature: String,
    /// Exact next diagnostic command for a user to run.
    pub next_diagnostic_command: String,
    /// Support-taxonomy claim — must NOT be promoted into a
    /// semantic-parity assertion. The dossier checks that any
    /// non-trivial support claim has a matching semantic_overlay
    /// artifact_ref.
    pub support_taxonomy_claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dossier {
    pub schema_version: String,
    pub source_commit: String,
    pub practical_recommendation: String,
    pub replacement_level: String,
    pub first_failing_blocker: String,
    pub top_decision_terms: Vec<String>,
    pub strict_hardened_divergence_signature: String,
    pub next_diagnostic_command: String,
    pub support_taxonomy_claim: String,
    /// Every evidence row that contributed to the dossier — name,
    /// summary, artifact_refs, source_commit. Sorted by kind.
    pub evidence_rows: Vec<DossierEvidenceRow>,
    /// Union of every artifact_ref across all input rows, deduped
    /// and sorted.
    pub all_artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DossierEvidenceRow {
    pub kind: String,
    pub summary: String,
    pub artifact_refs: Vec<String>,
    pub source_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DossierError {
    MissingArtifactRefs { kind: &'static str },
    StaleSourceCommit { kind: &'static str },
    MissingRequiredInput { kind: &'static str },
    SupportTaxonomyPromotedWithoutSemanticParity { claim: String },
    EmptyReplacementLevel,
}

impl core::fmt::Display for DossierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DossierError::MissingArtifactRefs { kind } => {
                write!(f, "{kind} input has empty artifact_refs")
            }
            DossierError::StaleSourceCommit { kind } => {
                write!(f, "{kind} input has stale source_commit")
            }
            DossierError::MissingRequiredInput { kind } => {
                write!(f, "{kind} input is required and missing")
            }
            DossierError::SupportTaxonomyPromotedWithoutSemanticParity { claim } => {
                write!(
                    f,
                    "support_taxonomy claim {claim:?} promoted without a paired semantic_overlay artifact_ref"
                )
            }
            DossierError::EmptyReplacementLevel => f.write_str("replacement_level is empty"),
        }
    }
}

impl std::error::Error for DossierError {}

#[derive(Debug)]
pub enum DossierLoadError {
    MissingEvidenceFile {
        kind: &'static str,
        path: PathBuf,
    },
    EvidenceReadFailed {
        kind: &'static str,
        path: PathBuf,
        message: String,
    },
    InvalidJson {
        kind: &'static str,
        path: PathBuf,
        message: String,
    },
    MissingJsonPointer {
        kind: &'static str,
        pointer: &'static str,
    },
    InvalidJsonPointerType {
        kind: &'static str,
        pointer: &'static str,
    },
    StaleSourceCommit {
        kind: &'static str,
        expected: String,
        observed: String,
    },
    EmptyReplacementLevel,
}

impl core::fmt::Display for DossierLoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DossierLoadError::MissingEvidenceFile { kind, path } => {
                write!(f, "{kind} evidence file is missing: {}", path.display())
            }
            DossierLoadError::EvidenceReadFailed {
                kind,
                path,
                message,
            } => write!(
                f,
                "{kind} evidence file could not be read at {}: {message}",
                path.display()
            ),
            DossierLoadError::InvalidJson {
                kind,
                path,
                message,
            } => write!(
                f,
                "{kind} evidence file is not valid JSON at {}: {message}",
                path.display()
            ),
            DossierLoadError::MissingJsonPointer { kind, pointer } => {
                write!(f, "{kind} evidence is missing JSON pointer {pointer}")
            }
            DossierLoadError::InvalidJsonPointerType { kind, pointer } => {
                write!(f, "{kind} JSON pointer {pointer} must resolve to a string")
            }
            DossierLoadError::StaleSourceCommit {
                kind,
                expected,
                observed,
            } => write!(
                f,
                "{kind} source_commit is stale: observed {observed:?}, expected {expected:?}"
            ),
            DossierLoadError::EmptyReplacementLevel => {
                f.write_str("l1_dashboard_row replacement level is empty")
            }
        }
    }
}

impl std::error::Error for DossierLoadError {}

fn evidence_path(kind: EvidenceKind) -> &'static DossierEvidencePath {
    DOSSIER_EVIDENCE_PATHS
        .iter()
        .find(|entry| entry.kind == kind)
        .expect("every EvidenceKind must have a DOSSIER_EVIDENCE_PATHS entry")
}

fn read_evidence_value(
    workspace_root: &Path,
    entry: &DossierEvidencePath,
) -> Result<Value, DossierLoadError> {
    let full_path = workspace_root.join(entry.path);
    let content = match std::fs::read_to_string(&full_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(DossierLoadError::MissingEvidenceFile {
                kind: entry.kind_label,
                path: full_path,
            });
        }
        Err(err) => {
            return Err(DossierLoadError::EvidenceReadFailed {
                kind: entry.kind_label,
                path: full_path,
                message: err.to_string(),
            });
        }
    };
    if entry.path.ends_with(".jsonl") {
        read_jsonl_evidence(entry, &full_path, &content)
    } else {
        serde_json::from_str(&content).map_err(|err| DossierLoadError::InvalidJson {
            kind: entry.kind_label,
            path: full_path,
            message: err.to_string(),
        })
    }
}

fn read_jsonl_evidence(
    entry: &DossierEvidencePath,
    full_path: &Path,
    content: &str,
) -> Result<Value, DossierLoadError> {
    let mut rows = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let row: Value =
            serde_json::from_str(trimmed).map_err(|err| DossierLoadError::InvalidJson {
                kind: entry.kind_label,
                path: full_path.to_path_buf(),
                message: format!("line {}: {err}", line_idx + 1),
            })?;
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(DossierLoadError::InvalidJson {
            kind: entry.kind_label,
            path: full_path.to_path_buf(),
            message: "jsonl file has no non-empty rows".to_string(),
        });
    }
    if rows.len() == 1 {
        return Ok(rows.remove(0));
    }

    let source_commit = rows
        .iter()
        .find_map(|row| row.pointer("/source_commit").and_then(Value::as_str))
        .unwrap_or_default()
        .to_string();
    let summary = rows
        .iter()
        .find_map(|row| row.pointer("/summary").and_then(Value::as_str))
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} evidence rows", rows.len()));
    let mut object = serde_json::Map::new();
    object.insert("summary".to_string(), Value::String(summary));
    object.insert("source_commit".to_string(), Value::String(source_commit));
    object.insert("rows".to_string(), Value::Array(rows));
    Ok(Value::Object(object))
}

fn json_string_at(
    kind: &'static str,
    value: &Value,
    pointer: &'static str,
) -> Result<String, DossierLoadError> {
    let Some(raw) = value.pointer(pointer) else {
        return Err(DossierLoadError::MissingJsonPointer { kind, pointer });
    };
    raw.as_str()
        .map(str::to_string)
        .ok_or(DossierLoadError::InvalidJsonPointerType { kind, pointer })
}

fn normalized_source_commit(
    kind: &'static str,
    observed: String,
    expected_commit: &str,
) -> Result<String, DossierLoadError> {
    if observed == expected_commit || observed == "current" {
        Ok(expected_commit.to_string())
    } else {
        Err(DossierLoadError::StaleSourceCommit {
            kind,
            expected: expected_commit.to_string(),
            observed,
        })
    }
}

fn evidence_ref_from_value(
    entry: &DossierEvidencePath,
    value: &Value,
    expected_commit: &str,
) -> Result<EvidenceRef, DossierLoadError> {
    let summary = json_string_at(entry.kind_label, value, entry.summary_pointer)?;
    let observed = json_string_at(entry.kind_label, value, entry.source_commit_pointer)?;
    let source_commit = normalized_source_commit(entry.kind_label, observed, expected_commit)?;
    Ok(EvidenceRef {
        kind: entry.kind,
        artifact_refs: vec![entry.path.to_string()],
        source_commit,
        summary,
    })
}

pub fn extract_replacement_level(l1_dashboard: &Value) -> Result<String, DossierLoadError> {
    let kind = EvidenceKind::L1DashboardRow.label();
    let level = json_string_at(kind, l1_dashboard, "/summary/replacement_level")?;
    if level.is_empty() {
        return Err(DossierLoadError::EmptyReplacementLevel);
    }
    Ok(level)
}

pub fn extract_first_failing_blocker(standalone_snapshot: &Value) -> String {
    fn scan(value: &Value) -> Option<String> {
        match value {
            Value::Array(rows) => rows.iter().find_map(scan),
            Value::Object(object) => {
                if object
                    .get("claim_status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status == "claim_blocked")
                {
                    for key in [
                        "failure_signature",
                        "blocker",
                        "blocker_id",
                        "id",
                        "description",
                    ] {
                        if let Some(text) = object.get(key).and_then(Value::as_str)
                            && !text.is_empty()
                        {
                            return Some(text.to_string());
                        }
                    }
                    return Some("claim_blocked".to_string());
                }
                object.values().find_map(scan)
            }
            _ => None,
        }
    }

    scan(standalone_snapshot).unwrap_or_default()
}

fn extract_top_decision_terms(runtime_decision_log: &Value) -> Vec<String> {
    runtime_decision_log
        .pointer("/top_decision_terms")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|term| !term.is_empty())
                .map(str::to_string)
                .collect()
        })
        .filter(|terms: &Vec<String>| !terms.is_empty())
        .unwrap_or_else(|| {
            runtime_decision_log
                .pointer("/summary")
                .and_then(Value::as_str)
                .map(|summary| vec![summary.to_string()])
                .unwrap_or_default()
        })
}

fn extract_optional_string(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Load canonical on-disk evidence rows and build the input bundle for
/// [`build_dossier`]. Checked-in files may use `source_commit: "current"`;
/// the loader normalizes that marker to `expected_commit` before returning.
pub fn load_dossier_inputs_from_disk(
    workspace_root: impl AsRef<Path>,
    expected_commit: &str,
) -> Result<DossierInputs, DossierLoadError> {
    let root = workspace_root.as_ref();
    let workload_entry = evidence_path(EvidenceKind::WorkloadReplay);
    let runtime_entry = evidence_path(EvidenceKind::RuntimeDecisionLog);
    let standalone_entry = evidence_path(EvidenceKind::StandaloneBlockerSnapshot);
    let l1_entry = evidence_path(EvidenceKind::L1DashboardRow);
    let semantic_entry = evidence_path(EvidenceKind::SemanticOverlay);

    let workload_value = read_evidence_value(root, workload_entry)?;
    let workload_replay =
        evidence_ref_from_value(workload_entry, &workload_value, expected_commit)?;
    let runtime_value = read_evidence_value(root, runtime_entry)?;
    let runtime_decision_log =
        evidence_ref_from_value(runtime_entry, &runtime_value, expected_commit)?;
    let standalone_value = read_evidence_value(root, standalone_entry)?;
    let standalone_blocker_snapshot =
        evidence_ref_from_value(standalone_entry, &standalone_value, expected_commit)?;
    let l1_value = read_evidence_value(root, l1_entry)?;
    let l1_dashboard_row = evidence_ref_from_value(l1_entry, &l1_value, expected_commit)?;
    let semantic_value = read_evidence_value(root, semantic_entry)?;
    let semantic_overlay =
        evidence_ref_from_value(semantic_entry, &semantic_value, expected_commit)?;

    let replacement_level = extract_replacement_level(&l1_value)?;
    let first_failing_blocker = extract_first_failing_blocker(&standalone_value);
    let top_decision_terms = extract_top_decision_terms(&runtime_value);
    let strict_hardened_divergence_signature =
        extract_optional_string(&runtime_value, "/strict_hardened_divergence_signature");
    let next_diagnostic_command =
        extract_optional_string(&l1_value, "/summary/next_diagnostic_command");
    let support_taxonomy_claim = semantic_value
        .pointer("/summary/blocked_claim")
        .and_then(Value::as_str)
        .unwrap_or("Semantic overlay loaded; support taxonomy remains reachability-only.")
        .to_string();

    Ok(DossierInputs {
        workload_replay: Some(workload_replay),
        runtime_decision_log: Some(runtime_decision_log),
        standalone_blocker_snapshot: Some(standalone_blocker_snapshot),
        l1_dashboard_row: Some(l1_dashboard_row),
        semantic_overlay: Some(semantic_overlay),
        replacement_level,
        first_failing_blocker,
        top_decision_terms,
        strict_hardened_divergence_signature,
        next_diagnostic_command,
        support_taxonomy_claim,
    })
}

fn validate_evidence(
    kind_label: &'static str,
    ev: &EvidenceRef,
    expected_commit: &str,
) -> Result<(), DossierError> {
    if ev.artifact_refs.is_empty() {
        return Err(DossierError::MissingArtifactRefs { kind: kind_label });
    }
    if ev.source_commit.is_empty() || ev.source_commit != expected_commit {
        return Err(DossierError::StaleSourceCommit { kind: kind_label });
    }
    Ok(())
}

/// Build a deterministic [`Dossier`] from the inputs. `expected_commit`
/// is the run's canonical source_commit — every input row must match.
pub fn build_dossier(
    inputs: &DossierInputs,
    expected_commit: &str,
) -> Result<Dossier, DossierError> {
    if inputs.replacement_level.is_empty() {
        return Err(DossierError::EmptyReplacementLevel);
    }

    let required_pairs: [(&'static str, Option<&EvidenceRef>); 5] = [
        ("workload_replay", inputs.workload_replay.as_ref()),
        ("runtime_decision_log", inputs.runtime_decision_log.as_ref()),
        (
            "standalone_blocker_snapshot",
            inputs.standalone_blocker_snapshot.as_ref(),
        ),
        ("l1_dashboard_row", inputs.l1_dashboard_row.as_ref()),
        ("semantic_overlay", inputs.semantic_overlay.as_ref()),
    ];
    for (label, ev) in &required_pairs {
        let Some(ev) = ev else {
            return Err(DossierError::MissingRequiredInput { kind: label });
        };
        validate_evidence(label, ev, expected_commit)?;
    }

    // Support-taxonomy guard: any non-trivial support claim that
    // contains the word "passes" or "ready" must have a matching
    // semantic_overlay artifact_ref. The semantic_overlay is the
    // ONLY evidence that supports a parity claim; other rows are
    // about reachability, not parity.
    let claim_lower = inputs.support_taxonomy_claim.to_lowercase();
    if claim_lower.contains("passes") || claim_lower.contains("ready") {
        let Some(overlay) = inputs.semantic_overlay.as_ref() else {
            return Err(DossierError::SupportTaxonomyPromotedWithoutSemanticParity {
                claim: inputs.support_taxonomy_claim.clone(),
            });
        };
        if overlay.artifact_refs.is_empty() {
            return Err(DossierError::SupportTaxonomyPromotedWithoutSemanticParity {
                claim: inputs.support_taxonomy_claim.clone(),
            });
        }
    }

    // Compose evidence rows in deterministic kind order.
    let evidence_rows: Vec<DossierEvidenceRow> = required_pairs
        .iter()
        .filter_map(|(label, ev)| {
            ev.map(|e| DossierEvidenceRow {
                kind: label.to_string(),
                summary: e.summary.clone(),
                artifact_refs: e.artifact_refs.clone(),
                source_commit: e.source_commit.clone(),
            })
        })
        .collect();
    // Stable sort by kind label (already in kind order via input
    // tuple order, but make it explicit for readers).
    let mut evidence_rows_sorted = evidence_rows.clone();
    evidence_rows_sorted.sort_by(|a, b| a.kind.cmp(&b.kind));

    // Union of artifact_refs across every kept row, deduped + sorted.
    let mut union: BTreeSet<String> = BTreeSet::new();
    for r in &evidence_rows_sorted {
        for a in &r.artifact_refs {
            union.insert(a.clone());
        }
    }
    let all_artifact_refs: Vec<String> = union.into_iter().collect();

    // Practical recommendation: derived deterministically from the
    // first failing blocker + divergence presence.
    let practical_recommendation = if !inputs.first_failing_blocker.is_empty() {
        format!(
            "Resolve the first failing blocker `{}` before promoting; replay any artifact_refs above to confirm.",
            inputs.first_failing_blocker
        )
    } else if !inputs.strict_hardened_divergence_signature.is_empty() {
        format!(
            "Strict/hardened divergence detected (`{}`); minimize via the bd-juvqm.6 trace minimizer before promoting.",
            inputs.strict_hardened_divergence_signature
        )
    } else {
        "No blocker rows; replay artifact_refs to confirm semantic parity before promoting."
            .to_string()
    };

    // Use the EvidenceKind labels to keep the public schema
    // self-documenting, even when an input is None.
    let _kind_labels: Vec<&'static str> = [
        EvidenceKind::WorkloadReplay,
        EvidenceKind::RuntimeDecisionLog,
        EvidenceKind::StandaloneBlockerSnapshot,
        EvidenceKind::L1DashboardRow,
        EvidenceKind::SemanticOverlay,
    ]
    .iter()
    .map(|k| k.label())
    .collect();

    Ok(Dossier {
        schema_version: "v1".to_string(),
        source_commit: expected_commit.to_string(),
        practical_recommendation,
        replacement_level: inputs.replacement_level.clone(),
        first_failing_blocker: inputs.first_failing_blocker.clone(),
        top_decision_terms: inputs.top_decision_terms.clone(),
        strict_hardened_divergence_signature: inputs.strict_hardened_divergence_signature.clone(),
        next_diagnostic_command: inputs.next_diagnostic_command.clone(),
        support_taxonomy_claim: inputs.support_taxonomy_claim.clone(),
        evidence_rows: evidence_rows_sorted,
        all_artifact_refs,
    })
}

/// Optional markdown rendering — same semantic content as JSON,
/// formatted for a human reader.
pub fn render_markdown(dossier: &Dossier) -> String {
    let mut s = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(&mut s, "# FrankenLibC explain dossier");
    let _ = writeln!(&mut s, "source_commit: {}", dossier.source_commit);
    let _ = writeln!(&mut s);
    let _ = writeln!(
        &mut s,
        "## Practical recommendation\n\n{}\n",
        dossier.practical_recommendation
    );
    let _ = writeln!(
        &mut s,
        "## Replacement level\n\n{}\n",
        dossier.replacement_level
    );
    let _ = writeln!(
        &mut s,
        "## First failing blocker\n\n{}\n",
        if dossier.first_failing_blocker.is_empty() {
            "(none)"
        } else {
            &dossier.first_failing_blocker
        }
    );
    let _ = writeln!(&mut s, "## Top decision evidence terms\n");
    for t in &dossier.top_decision_terms {
        let _ = writeln!(&mut s, "  - {t}");
    }
    let _ = writeln!(
        &mut s,
        "\n## Strict/hardened divergence summary\n\n{}\n",
        if dossier.strict_hardened_divergence_signature.is_empty() {
            "(none)"
        } else {
            &dossier.strict_hardened_divergence_signature
        }
    );
    let _ = writeln!(
        &mut s,
        "## Exact next diagnostic command\n\n```\n{}\n```\n",
        dossier.next_diagnostic_command
    );
    let _ = writeln!(
        &mut s,
        "## Support-taxonomy claim (NOT a parity claim)\n\n{}\n",
        dossier.support_taxonomy_claim
    );
    let _ = writeln!(&mut s, "## Cited artifacts\n");
    for r in &dossier.evidence_rows {
        let _ = writeln!(&mut s, "  - {} (source_commit {})", r.kind, r.source_commit);
        for a in &r.artifact_refs {
            let _ = writeln!(&mut s, "    - {a}");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EvidenceKind, refs: &[&str], summary: &str, commit: &str) -> EvidenceRef {
        EvidenceRef {
            kind,
            artifact_refs: refs.iter().map(|s| s.to_string()).collect(),
            source_commit: commit.to_string(),
            summary: summary.to_string(),
        }
    }

    fn healthy_inputs(commit: &str) -> DossierInputs {
        DossierInputs {
            workload_replay: Some(ev(
                EvidenceKind::WorkloadReplay,
                &["target/.../workload_replay.log"],
                "10/10 replay cases pass",
                commit,
            )),
            runtime_decision_log: Some(ev(
                EvidenceKind::RuntimeDecisionLog,
                &["target/.../runtime_decision.log.jsonl"],
                "Allow=124, Repair=3, Deny=0",
                commit,
            )),
            standalone_blocker_snapshot: Some(ev(
                EvidenceKind::StandaloneBlockerSnapshot,
                &["tests/conformance/standalone_replacement_artifact.v1.json"],
                "12 unwind blockers + 1 TLS blocker",
                commit,
            )),
            l1_dashboard_row: Some(ev(
                EvidenceKind::L1DashboardRow,
                &["tests/conformance/replacement_level_dashboard.v1.json"],
                "level=preload",
                commit,
            )),
            semantic_overlay: Some(ev(
                EvidenceKind::SemanticOverlay,
                &["tests/conformance/semantic_contract_inventory.v1.json"],
                "0 contracts violated, 1 reduced",
                commit,
            )),
            replacement_level: "preload".to_string(),
            first_failing_blocker: "host_libgcc_dependency".to_string(),
            top_decision_terms: vec!["pointer.validate_region".to_string()],
            strict_hardened_divergence_signature: String::new(),
            next_diagnostic_command:
                "rch cargo test -p frankenlibc-harness --test runtime_evidence_replay_gate_test"
                    .to_string(),
            support_taxonomy_claim: "Works under preload (reachability only — NOT a parity claim)"
                .to_string(),
        }
    }

    #[test]
    fn healthy_inputs_yield_valid_dossier() {
        let commit = "deadbeef".repeat(5);
        let dossier = build_dossier(&healthy_inputs(&commit), &commit).unwrap();
        assert_eq!(dossier.schema_version, "v1");
        assert_eq!(dossier.source_commit, commit);
        assert_eq!(dossier.evidence_rows.len(), 5);
        assert!(!dossier.all_artifact_refs.is_empty());
        assert!(
            dossier
                .practical_recommendation
                .contains("host_libgcc_dependency")
        );
    }

    #[test]
    fn dossier_is_deterministic_for_identical_inputs() {
        let commit = "abc123".repeat(7);
        let inputs = healthy_inputs(&commit);
        let a = build_dossier(&inputs, &commit).unwrap();
        let b = build_dossier(&inputs, &commit).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn missing_artifact_refs_is_rejected() {
        let commit = "deadbeef".repeat(5);
        let mut inputs = healthy_inputs(&commit);
        inputs
            .workload_replay
            .as_mut()
            .unwrap()
            .artifact_refs
            .clear();
        match build_dossier(&inputs, &commit) {
            Err(DossierError::MissingArtifactRefs {
                kind: "workload_replay",
            }) => {}
            other => panic!("expected MissingArtifactRefs; got {other:?}"),
        }
    }

    #[test]
    fn stale_source_commit_is_rejected() {
        let commit = "deadbeef".repeat(5);
        let mut inputs = healthy_inputs(&commit);
        inputs.runtime_decision_log.as_mut().unwrap().source_commit = "stale".to_string();
        match build_dossier(&inputs, &commit) {
            Err(DossierError::StaleSourceCommit {
                kind: "runtime_decision_log",
            }) => {}
            other => panic!("expected StaleSourceCommit; got {other:?}"),
        }
    }

    #[test]
    fn missing_required_input_is_rejected() {
        let commit = "deadbeef".repeat(5);
        let mut inputs = healthy_inputs(&commit);
        inputs.semantic_overlay = None;
        match build_dossier(&inputs, &commit) {
            Err(DossierError::MissingRequiredInput {
                kind: "semantic_overlay",
            }) => {}
            other => panic!("expected MissingRequiredInput(semantic_overlay); got {other:?}"),
        }
    }

    #[test]
    fn support_taxonomy_promotion_without_semantic_parity_is_rejected() {
        let commit = "deadbeef".repeat(5);
        let mut inputs = healthy_inputs(&commit);
        inputs.support_taxonomy_claim = "passes all CI lanes — ready to promote".to_string();
        // Drop the semantic_overlay artifact_refs to remove parity backing.
        inputs
            .semantic_overlay
            .as_mut()
            .unwrap()
            .artifact_refs
            .clear();
        match build_dossier(&inputs, &commit) {
            Err(DossierError::MissingArtifactRefs {
                kind: "semantic_overlay",
            }) => {
                // The artifact_refs check fires first — also acceptable.
            }
            Err(DossierError::SupportTaxonomyPromotedWithoutSemanticParity { .. }) => {}
            other => panic!("expected support taxonomy or artifact_refs rejection; got {other:?}"),
        }
    }

    #[test]
    fn dossier_cites_artifact_refs_for_every_evidence_row() {
        let commit = "deadbeef".repeat(5);
        let dossier = build_dossier(&healthy_inputs(&commit), &commit).unwrap();
        for r in &dossier.evidence_rows {
            assert!(
                !r.artifact_refs.is_empty(),
                "row {} must have artifact_refs",
                r.kind
            );
            assert_eq!(
                r.source_commit, commit,
                "row {} must cite source_commit",
                r.kind
            );
        }
    }

    #[test]
    fn markdown_render_includes_required_sections() {
        let commit = "deadbeef".repeat(5);
        let dossier = build_dossier(&healthy_inputs(&commit), &commit).unwrap();
        let md = render_markdown(&dossier);
        for section in [
            "Practical recommendation",
            "Replacement level",
            "First failing blocker",
            "Top decision evidence terms",
            "Strict/hardened divergence summary",
            "Exact next diagnostic command",
            "Support-taxonomy claim",
            "Cited artifacts",
        ] {
            assert!(md.contains(section), "markdown must contain `{section}`");
        }
    }

    #[test]
    fn dossier_recommendation_changes_with_divergence_presence() {
        let commit = "deadbeef".repeat(5);
        let mut inputs = healthy_inputs(&commit);
        inputs.first_failing_blocker = String::new();
        inputs.strict_hardened_divergence_signature = "stdio::fread::slow::adversarial".to_string();
        let dossier = build_dossier(&inputs, &commit).unwrap();
        assert!(
            dossier
                .practical_recommendation
                .contains("Strict/hardened divergence detected")
        );
    }
}
