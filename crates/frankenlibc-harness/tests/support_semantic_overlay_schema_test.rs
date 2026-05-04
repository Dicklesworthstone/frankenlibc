//! Integration test: support semantic overlay schema gate (bd-bp8fl.1.5)
//!
//! Verifies that support_semantic_overlay.v1.json remains a machine-readable
//! source of truth and cannot drift into malformed, stale, duplicate, or
//! over-promoted semantic claim evidence.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const NORMALIZED_CLAIM_FIELDS: &[&str] = &[
    "symbol",
    "version_node",
    "api_family",
    "contract_status",
    "semantic_status",
    "oracle_kind",
    "runtime_mode",
    "replacement_level",
    "source_refs",
    "artifact_refs",
    "freshness_metadata",
    "known_limitations",
];

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "row_id",
    "symbol",
    "rule_id",
    "expected",
    "actual",
    "artifact_refs",
    "source_commit",
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
    let script = root.join("scripts/check_support_semantic_overlay_schema.sh");
    let out_dir = unique_temp_path("support-overlay-schema-out", "dir");
    let mut command = Command::new(&script);
    command.current_dir(&root);
    command.env("FLC_SUPPORT_SEMANTIC_OUT_DIR", &out_dir);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run support semantic overlay schema gate")
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

#[test]
fn schema_declares_required_rules_replays_and_log_contract() {
    let root = workspace_root();
    let schema = load_json(&root.join("tests/conformance/support_semantic_overlay_schema.v1.json"));
    assert_eq!(schema["schema_version"].as_str(), Some("v1"));
    assert_eq!(schema["bead"].as_str(), Some("bd-bp8fl.1.5"));

    for key in [
        "support_semantic_overlay",
        "support_matrix",
        "replacement_levels",
    ] {
        let rel = schema["inputs"][key].as_str().expect("input path");
        assert!(root.join(rel).exists(), "missing input {key}: {rel}");
    }

    let fields: HashSet<_> = schema["normalized_claim_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row.as_str().unwrap())
        .collect();
    assert_eq!(fields, NORMALIZED_CLAIM_FIELDS.iter().copied().collect());

    let log_fields: Vec<_> = schema["required_log_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap())
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let replay_kinds: HashSet<_> = schema["replay_cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        replay_kinds,
        [
            "clean",
            "missing_required_field",
            "unknown_status",
            "duplicate_symbol",
            "stale_source_ref",
            "incompatible_replacement_level",
            "malformed_json"
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn gate_passes_current_overlay_and_emits_report_log_and_normalized_rows() {
    let root = workspace_root();
    let script = root.join("scripts/check_support_semantic_overlay_schema.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_support_semantic_overlay_schema.sh must be executable"
        );
    }

    let output = run_gate_with_env(&[]);
    assert!(
        output.status.success(),
        "support semantic overlay schema gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["audited_entry_count"].as_u64(), Some(10));
    assert_eq!(
        report["summary"]["normalized_claim_row_count"].as_u64(),
        Some(38)
    );
    assert_eq!(
        report["summary"]["exact_symbol_reference_count"].as_u64(),
        Some(33)
    );
    assert_eq!(
        report["summary"]["wildcard_symbol_reference_count"].as_u64(),
        Some(4)
    );
    assert_eq!(
        report["summary"]["duplicate_symbol_version_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["stale_source_ref_count"].as_u64(),
        Some(0)
    );

    let sample = report["normalized_claim_row_sample"].as_array().unwrap();
    assert!(
        !sample.is_empty(),
        "normalized row sample should be present"
    );
    for field in NORMALIZED_CLAIM_FIELDS {
        assert!(
            sample[0].get(*field).is_some(),
            "normalized row sample missing {field}"
        );
    }

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
fn missing_required_row_field_fails() {
    let root = workspace_root();
    let mut overlay = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"));
    overlay["audited_entries"][0]
        .as_object_mut()
        .unwrap()
        .remove("semantic_class");
    let fixture = write_json_fixture("support-overlay-missing-field", &overlay);

    let output = run_gate_with_env(&[("FLC_SUPPORT_SEMANTIC_OVERLAY", &fixture)]);
    let report = assert_gate_fails_with(&output, "missing required field");
    assert_eq!(report["checks"]["overlay_rows"].as_str(), Some("fail"));
}

#[test]
fn unknown_semantic_or_support_status_fails() {
    let root = workspace_root();
    let mut overlay = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"));
    overlay["audited_entries"][0]["semantic_class"] = serde_json::json!("imaginary_semantics");
    overlay["audited_entries"][1]["support_matrix_status"] =
        serde_json::json!("DefinitelySupported");
    let fixture = write_json_fixture("support-overlay-unknown-status", &overlay);

    let output = run_gate_with_env(&[("FLC_SUPPORT_SEMANTIC_OVERLAY", &fixture)]);
    let report = assert_gate_fails_with(&output, "unknown");
    assert_eq!(report["checks"]["overlay_rows"].as_str(), Some("fail"));
}

#[test]
fn duplicate_symbol_version_node_fails() {
    let root = workspace_root();
    let mut overlay = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"));
    let duplicate = overlay["audited_entries"][1]["symbols"][0].clone();
    overlay["audited_entries"][2]["symbols"][0] = duplicate;
    let fixture = write_json_fixture("support-overlay-duplicate-symbol", &overlay);

    let output = run_gate_with_env(&[("FLC_SUPPORT_SEMANTIC_OVERLAY", &fixture)]);
    let report = assert_gate_fails_with(&output, "duplicate symbol/version");
    assert_eq!(report["checks"]["overlay_rows"].as_str(), Some("fail"));
    assert_eq!(
        report["summary"]["duplicate_symbol_version_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn stale_source_ref_fails() {
    let root = workspace_root();
    let mut overlay = load_json(&root.join("tests/conformance/support_semantic_overlay.v1.json"));
    overlay["audited_entries"][0]["source_line"] = serde_json::json!(999_999_999);
    let fixture = write_json_fixture("support-overlay-stale-source", &overlay);

    let output = run_gate_with_env(&[("FLC_SUPPORT_SEMANTIC_OVERLAY", &fixture)]);
    let report = assert_gate_fails_with(&output, "stale source ref");
    assert_eq!(report["checks"]["overlay_rows"].as_str(), Some("fail"));
    assert_eq!(
        report["summary"]["stale_source_ref_count"].as_u64(),
        Some(1)
    );
}

#[test]
fn incompatible_replacement_level_fails_for_blocked_semantics() {
    let root = workspace_root();
    let mut schema =
        load_json(&root.join("tests/conformance/support_semantic_overlay_schema.v1.json"));
    schema["default_replacement_level"] = serde_json::json!("L3");
    let fixture = write_json_fixture("support-overlay-incompatible-level", &schema);

    let output = run_gate_with_env(&[("FLC_SUPPORT_SEMANTIC_SCHEMA", &fixture)]);
    let report = assert_gate_fails_with(&output, "replacement level");
    assert_eq!(report["checks"]["overlay_rows"].as_str(), Some("fail"));
}

#[test]
fn malformed_overlay_json_fails_with_structured_report() {
    let fixture = unique_temp_path("support-overlay-malformed", "json");
    std::fs::write(&fixture, "{not valid json\n").expect("failed to write malformed fixture");

    let output = run_gate_with_env(&[("FLC_SUPPORT_SEMANTIC_OVERLAY", &fixture)]);
    let report = assert_gate_fails_with(&output, "failed to parse");
    assert_eq!(report["status"].as_str(), Some("fail"));
}
