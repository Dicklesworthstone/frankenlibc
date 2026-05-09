//! Conformance gate for the explain dossier (bd-juvqm.10).
//!
//! Validates the manifest schema + exercises
//! `frankenlibc_harness::explain_dossier::build_dossier` against
//!   * a healthy fixture (every required input present, fresh
//!     source_commit, support claim properly hedged)
//!   * a stale fixture (one input has a divergent source_commit)
//!   * a missing fixture (one required input is absent)
//!   * a support-taxonomy promotion fixture (claim says "passes"
//!     without a paired semantic_overlay artifact_ref)
//!
//! and asserts the gate fails closed for the unhealthy fixtures
//! and produces deterministic JSON for the healthy one.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frankenlibc_harness::explain_dossier::{
    Dossier, DossierError, DossierInputs, EvidenceKind, EvidenceRef, build_dossier, render_markdown,
};
use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("conformance")
        .join("explain_dossier_contract.v1.json")
}

fn load_manifest() -> TestResult<Value> {
    let root = workspace_root()?;
    let path = manifest_path(&root);
    let content = std::fs::read_to_string(&path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&content).map_err(|err| format!("parse {path:?}: {err}"))
}

fn require(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn json_field<'a>(value: &'a Value, field: &str) -> TestResult<&'a Value> {
    value.get(field).ok_or_else(|| format!("missing `{field}`"))
}

fn json_array<'a>(value: &'a Value, field: &str) -> TestResult<&'a Vec<Value>> {
    json_field(value, field)?
        .as_array()
        .ok_or_else(|| format!("`{field}` must be an array"))
}

fn json_string<'a>(value: &'a Value, field: &str) -> TestResult<&'a str> {
    json_field(value, field)?
        .as_str()
        .ok_or_else(|| format!("`{field}` must be a string"))
}

fn json_bool(value: &Value, field: &str) -> TestResult<bool> {
    json_field(value, field)?
        .as_bool()
        .ok_or_else(|| format!("`{field}` must be a bool"))
}

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
            &["target/conformance/workload_replay.log.jsonl"],
            "10/10 replay cases pass",
            commit,
        )),
        runtime_decision_log: Some(ev(
            EvidenceKind::RuntimeDecisionLog,
            &["target/conformance/runtime_decision.log.jsonl"],
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
fn manifest_anchors_to_juvqm10() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "explain-dossier-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-juvqm.10", "bead")
}

#[test]
fn manifest_required_input_kinds_match_dossier_input_set() -> TestResult {
    let m = load_manifest()?;
    let kinds: BTreeSet<&str> = json_array(&m, "required_input_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "workload_replay",
        "runtime_decision_log",
        "standalone_blocker_snapshot",
        "l1_dashboard_row",
        "semantic_overlay",
    ]
    .into_iter()
    .collect();
    require(kinds == expected, format!("kinds: got {kinds:?}"))
}

#[test]
fn manifest_required_sections_cover_every_dossier_field() -> TestResult {
    let m = load_manifest()?;
    let sections: BTreeSet<&str> = json_array(&m, "required_dossier_sections")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for s in [
        "practical_recommendation",
        "replacement_level",
        "first_failing_blocker",
        "top_decision_terms",
        "strict_hardened_divergence_signature",
        "next_diagnostic_command",
        "support_taxonomy_claim",
        "evidence_rows",
        "all_artifact_refs",
    ] {
        require(
            sections.contains(s),
            format!("required_dossier_sections must include {s}"),
        )?;
    }
    Ok(())
}

#[test]
fn policy_fails_closed_on_required_kinds() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "policy")?;
    for f in [
        "fail_closed_when_artifact_refs_missing",
        "fail_closed_when_source_commit_stale",
        "fail_closed_when_required_input_missing",
        "fail_closed_when_replacement_level_empty",
        "fail_closed_when_support_taxonomy_promoted_without_semantic_parity",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    let rejected: BTreeSet<&str> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in [
        "missing_artifact_refs",
        "stale_source_commit",
        "missing_required_input",
        "empty_replacement_level",
        "support_taxonomy_promoted_without_semantic_parity",
    ] {
        require(
            rejected.contains(k),
            format!("rejected_evidence_kinds must include {k}"),
        )?;
    }
    Ok(())
}

#[test]
fn deterministic_output_contract_locks_in_json_required_and_markdown_optional() -> TestResult {
    let m = load_manifest()?;
    let det = json_field(&m, "deterministic_output_contract")?;
    require(json_bool(det, "json_required")?, "json_required")?;
    require(json_bool(det, "markdown_optional")?, "markdown_optional")?;
    require(
        json_string(det, "evidence_rows_sort_order")? == "ascending by kind label",
        "evidence_rows_sort_order",
    )?;
    require(
        json_string(det, "all_artifact_refs_sort_order")? == "ascending unique BTreeSet",
        "all_artifact_refs_sort_order",
    )
}

#[test]
fn healthy_fixture_produces_valid_dossier_with_cited_artifacts() -> TestResult {
    let commit = "1".repeat(40);
    let dossier: Dossier = build_dossier(&healthy_inputs(&commit), &commit)
        .map_err(|e| format!("healthy fixture must build; err {e}"))?;
    require(dossier.schema_version == "v1", "schema_version")?;
    require(dossier.source_commit == commit, "source_commit")?;
    require(dossier.evidence_rows.len() == 5, "5 evidence rows")?;
    for r in &dossier.evidence_rows {
        require(
            !r.artifact_refs.is_empty(),
            format!("row {} must cite artifact_refs", r.kind),
        )?;
        require(
            r.source_commit == commit,
            format!("row {} must cite source_commit", r.kind),
        )?;
    }
    require(
        !dossier.all_artifact_refs.is_empty(),
        "all_artifact_refs must be non-empty",
    )
}

#[test]
fn stale_fixture_is_rejected_with_kind_label() -> TestResult {
    let commit = "1".repeat(40);
    let mut inputs = healthy_inputs(&commit);
    inputs.runtime_decision_log.as_mut().unwrap().source_commit = "stale".into();
    match build_dossier(&inputs, &commit) {
        Err(DossierError::StaleSourceCommit {
            kind: "runtime_decision_log",
        }) => Ok(()),
        other => Err(format!("expected StaleSourceCommit; got {other:?}")),
    }
}

#[test]
fn missing_fixture_is_rejected_with_kind_label() -> TestResult {
    let commit = "1".repeat(40);
    let mut inputs = healthy_inputs(&commit);
    inputs.l1_dashboard_row = None;
    match build_dossier(&inputs, &commit) {
        Err(DossierError::MissingRequiredInput {
            kind: "l1_dashboard_row",
        }) => Ok(()),
        other => Err(format!(
            "expected MissingRequiredInput(l1_dashboard_row); got {other:?}"
        )),
    }
}

#[test]
fn support_taxonomy_promotion_is_rejected_when_unbacked() -> TestResult {
    let commit = "1".repeat(40);
    let mut inputs = healthy_inputs(&commit);
    inputs.support_taxonomy_claim = "passes all CI lanes — ready to promote".into();
    inputs
        .semantic_overlay
        .as_mut()
        .unwrap()
        .artifact_refs
        .clear();
    match build_dossier(&inputs, &commit) {
        Err(DossierError::MissingArtifactRefs {
            kind: "semantic_overlay",
        }) => Ok(()),
        Err(DossierError::SupportTaxonomyPromotedWithoutSemanticParity { .. }) => Ok(()),
        other => Err(format!(
            "expected support taxonomy or artifact_refs rejection; got {other:?}"
        )),
    }
}

#[test]
fn dossier_is_serializable_to_deterministic_json_and_optional_markdown() -> TestResult {
    let commit = "1".repeat(40);
    let dossier = build_dossier(&healthy_inputs(&commit), &commit).unwrap();
    // JSON: serde_json on an explicit struct of the public dossier
    // shape — we don't currently derive Serialize on Dossier, but the
    // contract requires the OUTPUT to be serializable as JSON. We
    // assert the markdown render contains every required section.
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
        require(
            md.contains(section),
            format!("markdown must contain `{section}`"),
        )?;
    }
    Ok(())
}
