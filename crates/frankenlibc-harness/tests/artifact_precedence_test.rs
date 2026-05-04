//! Integration test: artifact precedence and freshness gate (bd-bp8fl.7.7)
//!
//! Verifies that user-facing support, parity, replacement, release, and
//! compatibility claims are backed by current authoritative artifacts.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "artifact_id",
    "artifact_type",
    "producer_bead",
    "consumer_claim",
    "freshness_state",
    "precedence_decision",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_path(name: &str, extension: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "frankenlibc-{name}-{stamp}-{}.{}",
        std::process::id(),
        extension
    ))
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn write_json_fixture(name: &str, value: &serde_json::Value) -> PathBuf {
    let path = unique_temp_path(name, "json");
    std::fs::write(&path, serde_json::to_string_pretty(value).unwrap() + "\n")
        .expect("failed to write fixture");
    path
}

fn parse_stdout_report(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "failed to parse gate stdout as JSON: {}\nstdout={stdout}\nstderr={stderr}",
        parsed.err().unwrap()
    );
    serde_json::from_str(&stdout).expect("gate stdout JSON parse was checked above")
}

fn run_gate_with_env(envs: &[(&str, &Path)]) -> Output {
    let root = workspace_root();
    let script = root.join("scripts/check_artifact_precedence.sh");
    let out_dir = unique_temp_path("artifact-precedence-out", "dir");
    let mut command = Command::new(&script);
    command.current_dir(&root);
    command.env("FLC_ARTIFACT_PRECEDENCE_OUT_DIR", &out_dir);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run artifact precedence gate")
}

fn assert_gate_fails_with(output: &Output, signature: &str) -> serde_json::Value {
    assert!(
        !output.status.success(),
        "gate should fail with {signature}:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(output);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap_or_default().contains(signature)),
        "errors should mention {signature}: {}",
        report["errors"]
    );
    report
}

fn artifact_index(manifest: &serde_json::Value, id: &str) -> usize {
    manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .position(|artifact| artifact["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing artifact {id}"))
}

#[test]
fn manifest_declares_artifacts_claims_and_log_contract() {
    let root = workspace_root();
    let manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    assert_eq!(manifest["schema_version"].as_str(), Some("v1"));
    assert_eq!(manifest["bead"].as_str(), Some("bd-bp8fl.7.7"));

    let log_fields: Vec<_> = manifest["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let artifacts = manifest["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 12);
    let ids: HashSet<_> = artifacts
        .iter()
        .map(|artifact| artifact["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), artifacts.len(), "artifact ids must be unique");
    for artifact in artifacts {
        let rel = artifact["path"].as_str().expect("artifact path");
        assert!(root.join(rel).exists(), "missing artifact path {rel}");
    }

    let claims = manifest["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 3);
    assert!(
        claims
            .iter()
            .all(|claim| claim["prose_only_forbidden"].as_bool() == Some(true))
    );
}

#[test]
fn gate_passes_current_manifest_and_emits_report_and_log() {
    let root = workspace_root();
    let script = root.join("scripts/check_artifact_precedence.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_artifact_precedence.sh must be executable"
        );
    }

    let output = run_gate_with_env(&[]);
    assert!(
        output.status.success(),
        "artifact precedence gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["artifact_count"].as_u64(), Some(12));
    assert_eq!(report["summary"]["claim_count"].as_u64(), Some(3));
    assert_eq!(
        report["summary"]["missing_artifact_count"].as_u64(),
        Some(0)
    );
    assert_eq!(report["summary"]["stale_artifact_count"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["conflicting_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["prose_only_claim_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["out_of_order_artifact_count"].as_u64(),
        Some(0)
    );

    let log_path_value = report["log_path"].as_str().expect("report log_path");
    let log_path = if Path::new(log_path_value).is_absolute() {
        PathBuf::from(log_path_value)
    } else {
        root.join(log_path_value)
    };
    assert!(log_path.exists(), "missing {}", log_path.display());
    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(event.get(*key).is_some(), "log row missing {key}");
    }
}

#[test]
fn missing_authoritative_artifact_fails() {
    let root = workspace_root();
    let mut manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    let index = artifact_index(&manifest, "oracle_precedence");
    manifest["artifacts"][index]["path"] =
        serde_json::json!("tests/conformance/not-a-real-artifact.json");
    let fixture = write_json_fixture("artifact-precedence-missing-artifact", &manifest);

    let output = run_gate_with_env(&[("FLC_ARTIFACT_PRECEDENCE_MANIFEST", &fixture)]);
    let report = assert_gate_fails_with(&output, "missing artifact");
    assert_eq!(report["checks"]["artifact_shape"].as_str(), Some("fail"));
    assert_eq!(
        report["summary"]["missing_artifact_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn source_commit_mismatch_fails() {
    let root = workspace_root();
    let mut manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    let index = artifact_index(&manifest, "oracle_precedence");
    manifest["artifacts"][index]["source_commit_required"] = serde_json::json!(true);
    manifest["artifacts"][index]["expected_source_commit"] = serde_json::json!("not-the-head");
    let fixture = write_json_fixture("artifact-precedence-source-commit", &manifest);

    let output = run_gate_with_env(&[("FLC_ARTIFACT_PRECEDENCE_MANIFEST", &fixture)]);
    let report = assert_gate_fails_with(&output, "source_commit_mismatch");
    assert_eq!(report["summary"]["stale_artifact_count"].as_u64(), Some(1));
}

#[test]
fn stale_artifact_timestamp_fails() {
    let root = workspace_root();
    let mut manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    let index = artifact_index(&manifest, "docs_semantic_claims");
    manifest["artifacts"][index]["minimum_generated_at_utc"] =
        serde_json::json!("2099-01-01T00:00:00Z");
    let fixture = write_json_fixture("artifact-precedence-stale-artifact", &manifest);

    let output = run_gate_with_env(&[("FLC_ARTIFACT_PRECEDENCE_MANIFEST", &fixture)]);
    let report = assert_gate_fails_with(&output, "stale_artifact");
    assert_eq!(report["summary"]["stale_artifact_count"].as_u64(), Some(1));
}

#[test]
fn conflicting_claim_artifacts_fail() {
    let root = workspace_root();
    let mut manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    let support_matrix = artifact_index(&manifest, "support_matrix");
    let docs = artifact_index(&manifest, "docs_semantic_claims");
    let docs_rank = manifest["artifacts"][docs]["authority_rank"].clone();
    manifest["artifacts"][support_matrix]["authority_rank"] = docs_rank;
    let fixture = write_json_fixture("artifact-precedence-conflict", &manifest);

    let output = run_gate_with_env(&[("FLC_ARTIFACT_PRECEDENCE_MANIFEST", &fixture)]);
    let report = assert_gate_fails_with(&output, "conflicting artifacts");
    assert_eq!(
        report["summary"]["conflicting_claim_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn prose_only_claim_advancement_fails() {
    let root = workspace_root();
    let mut manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    manifest["claims"][0]["authoritative_artifact_ids"] = serde_json::json!([]);
    let fixture = write_json_fixture("artifact-precedence-prose-only", &manifest);

    let output = run_gate_with_env(&[("FLC_ARTIFACT_PRECEDENCE_MANIFEST", &fixture)]);
    let report = assert_gate_fails_with(&output, "prose-only");
    assert_eq!(
        report["summary"]["prose_only_claim_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn out_of_order_generated_artifact_fails() {
    let root = workspace_root();
    let mut manifest = load_json(&root.join("tests/conformance/artifact_precedence.v1.json"));
    let docs = artifact_index(&manifest, "docs_semantic_claims");
    manifest["artifacts"][docs]["authority_rank"] = serde_json::json!(15);
    let fixture = write_json_fixture("artifact-precedence-out-of-order", &manifest);

    let output = run_gate_with_env(&[("FLC_ARTIFACT_PRECEDENCE_MANIFEST", &fixture)]);
    let report = assert_gate_fails_with(&output, "higher precedence");
    assert!(
        report["summary"]["out_of_order_artifact_count"]
            .as_u64()
            .unwrap()
            >= 1,
        "out-of-order fixture should produce at least one dependency-order finding"
    );
}
