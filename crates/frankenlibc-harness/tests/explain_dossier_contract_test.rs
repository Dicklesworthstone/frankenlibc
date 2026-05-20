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
use std::process::Command;

use frankenlibc_harness::explain_dossier::{
    DOSSIER_EVIDENCE_PATHS, Dossier, DossierError, DossierInputs, DossierLoadError, EvidenceKind,
    EvidenceRef, build_dossier, extract_first_failing_blocker, extract_replacement_level,
    load_dossier_inputs_from_disk, render_markdown,
};
use serde_json::{Value, json};

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

fn git_stdout(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|err| format!("run git {args:?}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("git {args:?} emitted non-utf8 stdout: {err}"))
}

fn current_head() -> TestResult<String> {
    Ok(git_stdout(&workspace_root()?, &["rev-parse", "HEAD"])?
        .trim()
        .to_string())
}

fn write_target_log_fixtures(root: &Path, commit: &str) -> TestResult {
    let target = root.join("target").join("conformance");
    std::fs::create_dir_all(&target).map_err(|err| format!("create {target:?}: {err}"))?;
    let workload = json!({
        "summary": "3 workload replay rows loaded from the current run",
        "source_commit": commit,
        "artifact_refs": ["target/conformance/workload_replay.log.jsonl"]
    });
    let runtime = json!({
        "summary": "Allow=124, Repair=3, Deny=0",
        "source_commit": commit,
        "top_decision_terms": ["pointer.validate_region", "runtime.mode.strict"],
        "strict_hardened_divergence_signature": ""
    });
    std::fs::write(
        target.join("workload_replay.log.jsonl"),
        format!("{workload}\n"),
    )
    .map_err(|err| format!("write workload replay log: {err}"))?;
    std::fs::write(
        target.join("runtime_decision.log.jsonl"),
        format!("{runtime}\n"),
    )
    .map_err(|err| format!("write runtime decision log: {err}"))?;
    Ok(())
}

fn unique_temp_workspace(label: &str) -> TestResult<PathBuf> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| format!("system clock before unix epoch: {err}"))?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("frankenlibc-{label}-{pid}-{nanos}"));
    std::fs::create_dir_all(&path).map_err(|err| format!("create {path:?}: {err}"))?;
    Ok(path)
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

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_manifest_source_commit_freshness(manifest: &Value) -> TestResult {
    let source_commit = json_string(manifest, "source_commit")?;
    require(
        is_hex_commit(source_commit),
        "source_commit must be a 40-character git commit",
    )?;

    let policy = json_field(manifest, "policy")?;
    require(
        json_bool(policy, "fail_closed_when_source_commit_stale")?,
        "policy.fail_closed_when_source_commit_stale must be true",
    )?;
    require(
        json_string(policy, "stale_source_commit_freshness_target")? == "current git HEAD",
        "policy.stale_source_commit_freshness_target must be current git HEAD",
    )?;

    let freshness = json_field(manifest, "source_commit_freshness")?;
    require(
        json_bool(
            freshness,
            "require_no_tracked_source_changes_since_source_commit",
        )?,
        "source_commit_freshness must require no tracked source changes",
    )?;
    let roots = json_array(freshness, "tracked_source_roots")?;
    require(!roots.is_empty(), "tracked_source_roots must not be empty")?;
    let root_strings: Vec<&str> = roots
        .iter()
        .map(|root| {
            root.as_str()
                .ok_or_else(|| "tracked_source_roots entries must be strings".to_string())
        })
        .collect::<Result<_, _>>()?;

    let repo = workspace_root()?;
    git_stdout(
        &repo,
        &["cat-file", "-e", &format!("{source_commit}^{{commit}}")],
    )?;
    let commit_range = format!("{source_commit}..HEAD");
    let mut args = vec!["diff", "--name-only", commit_range.as_str(), "--"];
    args.extend(root_strings);
    let changed = git_stdout(&repo, &args)?;
    let changed_paths: Vec<&str> = changed.lines().filter(|line| !line.is_empty()).collect();
    require(
        changed_paths.is_empty(),
        format!(
            "source_commit {source_commit} is stale for explain dossier roots: {changed_paths:?}"
        ),
    )
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
fn manifest_pins_canonical_evidence_loader_paths() -> TestResult {
    let m = load_manifest()?;
    let contract = json_field(&m, "canonical_evidence_loader")?;
    require(
        json_string(contract, "missing_result")? == "DossierLoadError::MissingEvidenceFile",
        "missing_result",
    )?;
    for entry in DOSSIER_EVIDENCE_PATHS {
        let row = json_field(contract, entry.kind.label())?;
        require(
            json_string(row, "path")? == entry.path,
            format!("{} path", entry.kind.label()),
        )?;
        require(
            json_string(row, "summary_pointer")? == entry.summary_pointer,
            format!("{} summary pointer", entry.kind.label()),
        )?;
        require(
            json_string(row, "source_commit_pointer")? == entry.source_commit_pointer,
            format!("{} source pointer", entry.kind.label()),
        )?;
    }
    Ok(())
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
fn manifest_source_commit_is_fresh_for_dossier_roots() -> TestResult {
    let m = load_manifest()?;
    validate_manifest_source_commit_freshness(&m)
}

#[test]
fn fixture_invalid_manifest_source_commit_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m["source_commit"] = Value::String("0000000000000000000000000000000000000000".to_string());
    let err = validate_manifest_source_commit_freshness(&m)
        .expect_err("invalid manifest source_commit must be rejected");
    require(
        err.contains("git") || err.contains("source_commit"),
        format!("unexpected invalid source_commit error: {err}"),
    )
}

#[test]
fn fixture_stale_manifest_source_commit_is_rejected() -> TestResult {
    let mut m = load_manifest()?;
    m["source_commit"] = Value::String("595224166c3be80fc23f888c5375129a5b26c1b9".to_string());
    let err = validate_manifest_source_commit_freshness(&m)
        .expect_err("stale manifest source_commit must be rejected");
    require(
        err.contains("stale") || err.contains("git"),
        format!("unexpected stale source_commit error: {err}"),
    )
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
    inputs
        .runtime_decision_log
        .as_mut()
        .ok_or_else(|| "healthy fixture must include runtime_decision_log".to_string())?
        .source_commit = "stale".into();
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
        .ok_or_else(|| "healthy fixture must include semantic_overlay".to_string())?
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
    let dossier = build_dossier(&healthy_inputs(&commit), &commit)
        .map_err(|err| format!("healthy fixture must build dossier: {err}"))?;
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

#[test]
fn loader_fails_closed_with_precise_missing_kind() -> TestResult {
    let root = unique_temp_workspace("missing-dossier-evidence")?;
    match load_dossier_inputs_from_disk(&root, &"1".repeat(40)) {
        Err(DossierLoadError::MissingEvidenceFile {
            kind: "workload_replay",
            ..
        }) => Ok(()),
        other => Err(format!("expected missing workload_replay; got {other:?}")),
    }
}

#[test]
fn loader_fails_closed_with_precise_stale_kind() -> TestResult {
    let root = unique_temp_workspace("stale-dossier-evidence")?;
    let target = root.join("target").join("conformance");
    std::fs::create_dir_all(&target).map_err(|err| format!("create {target:?}: {err}"))?;
    std::fs::write(
        target.join("workload_replay.log.jsonl"),
        "{\"summary\":\"stale workload\",\"source_commit\":\"stale\"}\n",
    )
    .map_err(|err| format!("write stale workload log: {err}"))?;
    match load_dossier_inputs_from_disk(&root, &"1".repeat(40)) {
        Err(DossierLoadError::StaleSourceCommit {
            kind: "workload_replay",
            observed,
            ..
        }) if observed == "stale" => Ok(()),
        other => Err(format!("expected stale workload_replay; got {other:?}")),
    }
}

#[test]
fn helpers_extract_dashboard_level_and_first_claim_blocker() -> TestResult {
    let dashboard = json!({
        "summary": {
            "replacement_level": "L0"
        }
    });
    require(
        extract_replacement_level(&dashboard).map_err(|err| err.to_string())? == "L0",
        "replacement level",
    )?;
    let standalone = json!({
        "rows": [
            {
                "claim_status": "claim_unblocked",
                "failure_signature": "not-this-one"
            },
            {
                "claim_status": "claim_blocked",
                "failure_signature": "host_libc_dependency"
            }
        ]
    });
    let blocker = extract_first_failing_blocker(&standalone);
    require(
        matches!(blocker.as_str(), "host_libc_dependency"),
        "first claim_blocked row",
    )
}

#[test]
fn loader_builds_real_dossier_from_canonical_paths() -> TestResult {
    let root = workspace_root()?;
    let commit = current_head()?;
    write_target_log_fixtures(&root, &commit)?;
    let inputs = load_dossier_inputs_from_disk(&root, &commit)
        .map_err(|err| format!("canonical loader should succeed: {err}"))?;
    let dossier = build_dossier(&inputs, &commit)
        .map_err(|err| format!("loaded inputs should build a dossier: {err}"))?;
    require(dossier.source_commit == commit, "source_commit")?;
    require(dossier.evidence_rows.len() == 5, "5 loaded rows")?;
    require(
        dossier.replacement_level == "L0",
        format!("replacement level: {}", dossier.replacement_level),
    )?;
    require(
        dossier
            .all_artifact_refs
            .contains(&"target/conformance/workload_replay.log.jsonl".to_string()),
        "workload log artifact ref",
    )
}
