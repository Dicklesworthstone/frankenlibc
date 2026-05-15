//! Conformance gate for the narrow asupersync Lab-backed replay
//! prototype (bd-juvqm.15).
//!
//! Validates the manifest schema + exercises
//! `frankenlibc_harness::asupersync_lab_replay::{validate_replay,
//! classify_outcome}` against a tiny deterministic fixture covering
//! all three terminal outcomes (Pass, CodeFailure, ToolFailure).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frankenlibc_harness::asupersync_lab_replay::{
    DETECTION_REASONS, DetectionEnv, ReplayOutcome, ReplayRecord, ReplayValidationError,
    classify_outcome, detect_asupersync_available, validate_replay,
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
        .join("asupersync_lab_replay_contract.v1.json")
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

fn deterministic_fixture(commit: &str) -> ReplayRecord {
    ReplayRecord {
        schema_version: "v1".to_string(),
        trace_class: "stdio.fread_small".to_string(),
        virtual_time_seed: 0xfeed_face,
        schedule_decisions: vec!["W:0".into(), "R:0".into(), "W:1".into(), "R:1".into()],
        replay_inputs: vec!["target/conformance/stdio_fread_small.input.jsonl".to_string()],
        expected_outputs: vec!["target/conformance/stdio_fread_small.expected.jsonl".to_string()],
        artifact_refs: vec![
            "target/conformance/stdio_fread_small.input.jsonl".to_string(),
            "target/conformance/stdio_fread_small.expected.jsonl".to_string(),
            "target/conformance/stdio_fread_small.observed.jsonl".to_string(),
        ],
        source_commit: commit.to_string(),
    }
}

#[test]
fn manifest_anchors_to_juvqm15_with_stdio_fread_small_trace() -> TestResult {
    let m = load_manifest()?;
    require(
        json_string(&m, "manifest_id")? == "asupersync-lab-replay-contract",
        "manifest_id",
    )?;
    require(json_string(&m, "bead")? == "bd-juvqm.15", "bead")?;
    let scope = json_field(&m, "narrow_scope")?;
    require(
        json_string(scope, "trace_class")? == "stdio.fread_small",
        "trace_class must be stdio.fread_small",
    )?;
    require(
        !json_bool(scope, "broad_workload_required")?,
        "broad_workload_required must be false (bead: tiny deterministic fixture)",
    )
}

#[test]
fn manifest_required_fields_match_replay_record_struct() -> TestResult {
    let m = load_manifest()?;
    let fields: BTreeSet<&str> = json_array(&m, "required_replay_record_fields")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "schema_version",
        "trace_class",
        "virtual_time_seed",
        "schedule_decisions",
        "replay_inputs",
        "expected_outputs",
        "artifact_refs",
        "source_commit",
    ]
    .into_iter()
    .collect();
    require(
        fields == expected,
        format!("required fields: got {fields:?}"),
    )
}

#[test]
fn outcome_classification_carries_pass_codefailure_toolfailure_with_disjoint_signatures()
-> TestResult {
    let m = load_manifest()?;
    let outcomes = json_array(json_field(&m, "outcome_classification")?, "outcomes")?;
    let ids: BTreeSet<&str> = outcomes
        .iter()
        .filter_map(|o| o.get("outcome_id").and_then(Value::as_str))
        .collect();
    let expected: BTreeSet<&str> = ["Pass", "CodeFailure", "ToolFailure"].into_iter().collect();
    require(ids == expected, format!("outcomes: got {ids:?}"))?;

    // Pass carries no signature; CodeFailure carries signature; ToolFailure carries reason.
    for o in outcomes {
        let id = json_string(o, "outcome_id")?;
        let carries_sig = o
            .get("carries_signature")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let carries_reason = o
            .get("carries_reason")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match id {
            "Pass" => require(!carries_sig && !carries_reason, "Pass carries nothing")?,
            "CodeFailure" => require(
                carries_sig && !carries_reason,
                "CodeFailure carries signature",
            )?,
            "ToolFailure" => require(!carries_sig && carries_reason, "ToolFailure carries reason")?,
            other => return Err(format!("unexpected outcome_id `{other}`")),
        }
    }
    Ok(())
}

#[test]
fn policy_fails_closed_on_required_kinds() -> TestResult {
    let m = load_manifest()?;
    let policy = json_field(&m, "policy")?;
    for f in [
        "fail_closed_when_required_field_missing",
        "fail_closed_when_source_commit_invalid",
        "fail_closed_when_replay_input_not_in_artifact_refs",
        "tool_failure_separation_required",
    ] {
        require(json_bool(policy, f)?, format!("{f} must be true"))?;
    }
    let rejected: BTreeSet<&str> = json_array(policy, "rejected_evidence_kinds")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for k in [
        "missing_required_field",
        "stale_or_invalid_source_commit",
        "replay_input_not_in_artifact_refs",
        "tool_failure_misclassified_as_code_failure",
    ] {
        require(
            rejected.contains(k),
            format!("rejected_evidence_kinds must include {k}"),
        )?;
    }
    Ok(())
}

#[test]
fn fallback_path_documents_tool_failure_reason_format() -> TestResult {
    let m = load_manifest()?;
    let fallback = json_field(&m, "fallback_path")?;
    let fmt_str = json_string(fallback, "tool_failure_reason_format")?;
    require(
        fmt_str.contains("asupersync tool unavailable"),
        "tool_failure_reason_format must mention `asupersync tool unavailable`",
    )?;
    require(
        fmt_str.contains("<id>"),
        "tool_failure_reason_format must template the trace_class id",
    )
}

#[test]
fn fixture_validates_clean() -> TestResult {
    let commit = "1".repeat(40);
    let r = deterministic_fixture(&commit);
    validate_replay(&r).map_err(|e| format!("clean fixture must validate; got {e}"))
}

#[test]
fn fixture_pass_outcome_when_observed_matches_expected() -> TestResult {
    let commit = "1".repeat(40);
    let r = deterministic_fixture(&commit);
    let outcome = classify_outcome(&r, true, &r.expected_outputs);
    require(
        matches!(outcome, ReplayOutcome::Pass),
        format!("expected Pass; got {outcome:?}"),
    )
}

#[test]
fn fixture_code_failure_outcome_when_observed_diverges() -> TestResult {
    let commit = "1".repeat(40);
    let r = deterministic_fixture(&commit);
    let observed = vec!["target/conformance/stdio_fread_small.divergent.jsonl".to_string()];
    match classify_outcome(&r, true, &observed) {
        ReplayOutcome::CodeFailure { signature } => {
            require(
                signature.starts_with("stdio.fread_small::"),
                "signature must namespace by trace_class",
            )?;
            require(
                signature.contains("missing=") && signature.contains("extra="),
                "signature must report missing + extra outputs",
            )
        }
        other => Err(format!("expected CodeFailure; got {other:?}")),
    }
}

#[test]
fn fixture_tool_failure_outcome_when_asupersync_unavailable() -> TestResult {
    let commit = "1".repeat(40);
    let r = deterministic_fixture(&commit);
    // Even with matching observed_outputs, asupersync_available=false MUST
    // produce ToolFailure — never Pass — to avoid hiding a tool-install
    // issue under a green CI badge.
    match classify_outcome(&r, false, &r.expected_outputs) {
        ReplayOutcome::ToolFailure { reason } => {
            require(
                reason.contains("asupersync tool unavailable"),
                "ToolFailure reason must mention tool unavailable",
            )?;
            require(
                reason.contains("stdio.fread_small"),
                "ToolFailure reason must include the trace_class",
            )
        }
        other => Err(format!("expected ToolFailure; got {other:?}")),
    }
}

#[test]
fn fixture_validate_rejects_invalid_source_commit() -> TestResult {
    let mut r = deterministic_fixture(&"1".repeat(40));
    r.source_commit = "not-a-sha".to_string();
    match validate_replay(&r) {
        Err(ReplayValidationError::StaleOrInvalidSourceCommit) => Ok(()),
        other => Err(format!(
            "expected StaleOrInvalidSourceCommit; got {other:?}"
        )),
    }
}

#[test]
fn fixture_validate_rejects_replay_input_not_in_artifact_refs() -> TestResult {
    let mut r = deterministic_fixture(&"1".repeat(40));
    r.replay_inputs.push("target/uncited.jsonl".to_string());
    match validate_replay(&r) {
        Err(ReplayValidationError::MissingArtifactRefs) => Ok(()),
        other => Err(format!("expected MissingArtifactRefs; got {other:?}")),
    }
}

// ── Detection contract tests (bd-qfbhc) ──────────────────────────────

fn empty_env() -> DetectionEnv {
    DetectionEnv {
        override_var: None,
        asupersync_dir: PathBuf::from("/nonexistent-asupersync-test-dir"),
        path_search_paths: vec![],
    }
}

#[test]
fn manifest_detection_contract_locks_probe_order_and_override_var() -> TestResult {
    let m = load_manifest()?;
    let det = json_field(&m, "detection_contract")?;
    require(
        json_string(det, "env_override_var")? == "FRANKENLIBC_ASUPERSYNC_AVAILABLE",
        "env_override_var",
    )?;
    require(
        json_string(det, "canonical_install_dir")? == "/dp/asupersync",
        "canonical_install_dir",
    )?;
    require(
        json_string(det, "binary_name_searched_on_path")? == "asupersync",
        "binary_name_searched_on_path",
    )?;
    let probe_order: Vec<&str> = json_array(det, "probe_order")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected = [
        "env_override_disabled",
        "env_override_enabled",
        "asupersync_dir_present",
        "binary_on_path",
        "no_install_detected",
    ];
    require(
        probe_order == expected,
        format!("probe_order: got {probe_order:?}"),
    )?;
    // The library's DETECTION_REASONS const must match the manifest probe_order set.
    let manifest_reasons: BTreeSet<&str> = probe_order.iter().copied().collect();
    let lib_reasons: BTreeSet<&str> = DETECTION_REASONS.iter().copied().collect();
    require(
        manifest_reasons == lib_reasons,
        format!("DETECTION_REASONS drift: lib={lib_reasons:?}, manifest={manifest_reasons:?}"),
    )
}

#[test]
fn detect_returns_no_install_detected_on_empty_env() -> TestResult {
    let r = detect_asupersync_available(&empty_env());
    require(!r.available, "available must be false")?;
    require(
        r.detection_reason == "no_install_detected",
        format!("got {}", r.detection_reason),
    )?;
    require(r.path.is_none(), "path must be None")
}

#[test]
fn env_override_disabled_short_circuits_regardless_of_fs_state() -> TestResult {
    // Even with a real asupersync_dir, FRANKENLIBC_ASUPERSYNC_AVAILABLE=0 wins.
    let mut env = empty_env();
    env.override_var = Some("0".to_string());
    env.asupersync_dir = std::env::temp_dir(); // exists
    let r = detect_asupersync_available(&env);
    require(!r.available, "override=0 must produce available=false")?;
    require(
        r.detection_reason == "env_override_disabled",
        format!("got {}", r.detection_reason),
    )
}

#[test]
fn env_override_enabled_short_circuits_regardless_of_fs_state() -> TestResult {
    // Even with NO asupersync_dir on disk, override=1 wins.
    let mut env = empty_env();
    env.override_var = Some("1".to_string());
    let r = detect_asupersync_available(&env);
    require(r.available, "override=1 must produce available=true")?;
    require(
        r.detection_reason == "env_override_enabled",
        format!("got {}", r.detection_reason),
    )
}

#[test]
fn env_override_truthy_aliases_match() -> TestResult {
    for v in ["true", "yes", "on"] {
        let mut env = empty_env();
        env.override_var = Some(v.to_string());
        let r = detect_asupersync_available(&env);
        require(
            r.available && r.detection_reason == "env_override_enabled",
            format!(
                "override={v}: got available={}, reason={}",
                r.available, r.detection_reason
            ),
        )?;
    }
    Ok(())
}

#[test]
fn env_override_falsy_aliases_match() -> TestResult {
    for v in ["false", "no", "off", ""] {
        let mut env = empty_env();
        env.override_var = Some(v.to_string());
        let r = detect_asupersync_available(&env);
        require(
            !r.available && r.detection_reason == "env_override_disabled",
            format!(
                "override={v:?}: got available={}, reason={}",
                r.available, r.detection_reason
            ),
        )?;
    }
    Ok(())
}

#[test]
fn asupersync_dir_present_branch_fires_when_dir_exists_and_no_override() -> TestResult {
    // Use temp_dir as a stand-in for a real install dir.
    let mut env = empty_env();
    env.asupersync_dir = std::env::temp_dir();
    let r = detect_asupersync_available(&env);
    require(r.available, "available must be true when dir exists")?;
    require(
        r.detection_reason == "asupersync_dir_present",
        format!("got {}", r.detection_reason),
    )?;
    require(
        r.path == Some(std::env::temp_dir()),
        "path must equal the dir",
    )
}

#[test]
fn binary_on_path_branch_fires_when_binary_exists_on_path() -> TestResult {
    // Find a binary that exists on /usr/bin (e.g. /bin/ls or /usr/bin/ls).
    // We don't actually need an asupersync binary — we synthesize one by
    // pointing path_search_paths at a dir we control with a fake file.
    let tmp = std::env::temp_dir().join(format!(
        "frankenlibc-asupersync-test-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).map_err(|e| format!("mkdir {tmp:?}: {e}"))?;
    let fake = tmp.join("asupersync");
    std::fs::write(&fake, b"#!/bin/sh\necho fake\n").map_err(|e| format!("write {fake:?}: {e}"))?;
    let mut env = empty_env();
    env.path_search_paths = vec![tmp.clone()];
    let r = detect_asupersync_available(&env);
    require(r.available, "available must be true when binary exists")?;
    require(
        r.detection_reason == "binary_on_path",
        format!("got {}", r.detection_reason),
    )?;
    require(r.path == Some(fake), "path must point at fake binary")?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

#[test]
fn detection_is_deterministic_for_a_given_env() -> TestResult {
    let mut env = empty_env();
    env.override_var = Some("1".to_string());
    let r1 = detect_asupersync_available(&env);
    let r2 = detect_asupersync_available(&env);
    require(r1 == r2, format!("{r1:?} vs {r2:?}"))
}

#[test]
fn detection_env_from_process_env_does_not_panic() -> TestResult {
    let env = DetectionEnv::from_process_env();
    let _r = detect_asupersync_available(&env);
    Ok(())
}
