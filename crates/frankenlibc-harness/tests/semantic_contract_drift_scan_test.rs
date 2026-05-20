//! Integration test: semantic contract drift scanner (bd-bp8fl.1.3)
//!
//! Verifies the CI gate that keeps no-op/fallback/unsupported/bootstrap
//! contract annotations synchronized with the semantic overlay inventory.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test semantic_contract_drift_scan_test

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "scanner_rule",
    "symbol",
    "file_path",
    "expected_contract",
    "actual_contract",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REQUIRED_RULES: &[&str] = &[
    "abi_export_input_presence",
    "docs_claim_surface",
    "inventory_marker_freshness",
    "semantic_join_freshness",
    "source_contract_annotation_drift",
    "support_taxonomy_claim_blocker",
];

const REQUIRED_REPLAY_KINDS: &[&str] = &["allowlisted", "clean", "new_drift", "stale_artifact"];

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn unique_temp_path(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("frankenlibc-{name}-{stamp}-{}", std::process::id()))
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
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
    let script = root.join("scripts/check_semantic_contract_drift.sh");
    let mut command = Command::new(&script);
    command.current_dir(&root);
    for (key, value) in envs {
        command.env(key, value);
    }
    command
        .output()
        .expect("failed to run semantic contract drift scanner")
}

#[test]
fn artifact_declares_inputs_rules_replays_and_log_contract() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/semantic_contract_drift_scan.v1.json"));

    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-bp8fl.1.3"));

    for key in [
        "semantic_contract_inventory",
        "semantic_contract_symbol_join",
        "support_semantic_overlay",
        "support_matrix",
        "version_script",
        "readme",
        "feature_parity",
    ] {
        let rel = artifact["inputs"][key].as_str().expect("input path");
        assert!(
            root.join(rel).exists(),
            "scanner input {key} should exist at {rel}"
        );
    }

    let rule_ids: HashSet<_> = artifact["scanner_rules"]
        .as_array()
        .expect("scanner_rules must be array")
        .iter()
        .map(|rule| rule["id"].as_str().expect("rule id"))
        .collect();
    assert_eq!(rule_ids, REQUIRED_RULES.iter().copied().collect());

    let log_fields: Vec<_> = artifact["required_log_fields"]
        .as_array()
        .expect("required_log_fields must be array")
        .iter()
        .map(|field| field.as_str().expect("field name"))
        .collect();
    assert_eq!(log_fields, REQUIRED_LOG_FIELDS);

    let replay_kinds: HashSet<_> = artifact["replay_cases"]
        .as_array()
        .expect("replay_cases must be array")
        .iter()
        .map(|case| case["kind"].as_str().expect("replay kind"))
        .collect();
    assert_eq!(
        replay_kinds,
        REQUIRED_REPLAY_KINDS.iter().copied().collect()
    );

    assert_eq!(
        artifact["claim_blocking_policy"]["support_taxonomy_stub_zero_is_not_semantic_parity"]
            .as_bool(),
        Some(true)
    );
    assert_eq!(
        artifact["claim_blocking_policy"]
            ["false_positive_allowlist_requires_symbol_and_evidence_reason"]
            .as_bool(),
        Some(true)
    );
}

#[test]
fn gate_passes_clean_tree_and_emits_report_and_required_log_fields() {
    let root = workspace_root();
    let script = root.join("scripts/check_semantic_contract_drift.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_semantic_contract_drift.sh must be executable"
        );
    }

    let output = run_gate_with_env(&[]);
    assert!(
        output.status.success(),
        "semantic contract drift scanner failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-bp8fl.1.3"));
    assert_eq!(report["status"].as_str(), Some("pass"));
    for rule in REQUIRED_RULES {
        assert_eq!(
            report["checks"][*rule].as_str(),
            Some("pass"),
            "checks.{rule} should pass"
        );
    }
    assert_eq!(
        report["summary"]["tracked_inventory_entries"].as_u64(),
        Some(18)
    );
    assert_eq!(
        report["summary"]["semantic_parity_blocker_count"].as_u64(),
        Some(18)
    );
    assert_eq!(
        report["summary"]["untracked_contract_annotation_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        report["summary"]["support_matrix_stub_count"].as_u64(),
        Some(0)
    );
    assert!(
        report["claim_surfaces_blocked_by_findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|surface| surface.as_str()
                == Some("support_matrix_stub_zero_full_replacement_claim"))
    );

    let log_path = root.join("target/conformance/semantic_contract_drift_scan.log.jsonl");
    assert!(log_path.exists(), "missing {}", log_path.display());
    let log_line = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log should contain at least one row")
        .to_string();
    let event: serde_json::Value = serde_json::from_str(&log_line).expect("log row should parse");
    for key in REQUIRED_LOG_FIELDS {
        assert!(
            event.get(*key).is_some(),
            "structured log row missing {key}"
        );
    }

    let report_path = root.join("target/conformance/semantic_contract_drift_scan.report.json");
    assert!(report_path.exists(), "missing {}", report_path.display());
}

#[test]
fn stale_inventory_marker_fails_with_stable_signature() {
    let root = workspace_root();
    let canonical_inventory = root.join("tests/conformance/semantic_contract_inventory.v1.json");
    let mutated_inventory = unique_temp_path("semantic-contract-drift-stale-inventory.json");
    let mut inventory = load_json(&canonical_inventory);
    inventory["entries"][0]["line_marker"] =
        serde_json::json!("this marker should not exist in the source file");
    std::fs::write(
        &mutated_inventory,
        serde_json::to_string_pretty(&inventory).unwrap() + "\n",
    )
    .expect("failed to write stale inventory fixture");

    let output = run_gate_with_env(&[("FLC_SEMANTIC_DRIFT_INVENTORY", &mutated_inventory)]);
    assert!(
        !output.status.success(),
        "stale inventory marker should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["inventory_marker_freshness"].as_str(),
        Some("fail")
    );
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or_default()
                .contains("stale line_marker")),
        "failure should identify stale line_marker"
    );
}

#[test]
fn new_untracked_contract_annotation_fails() {
    let root = workspace_root();
    let source = unique_temp_path("semantic-contract-new-drift.rs");
    std::fs::write(
        &source,
        "/// semantic contract: no-op fallback for fake_new_contract\npub fn fake_new_contract() {}\n",
    )
    .expect("failed to write source drift fixture");

    let artifact_path = unique_temp_path("semantic-contract-new-drift-artifact.json");
    let mut artifact =
        load_json(&root.join("tests/conformance/semantic_contract_drift_scan.v1.json"));
    artifact["source_scan_roots"] = serde_json::json!([source]);
    artifact["source_scan_suffixes"] = serde_json::json!([]);
    std::fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap() + "\n",
    )
    .expect("failed to write source drift artifact fixture");

    let output = run_gate_with_env(&[("FLC_SEMANTIC_DRIFT_ARTIFACT", &artifact_path)]);
    assert!(
        !output.status.success(),
        "untracked contract annotation should fail:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert_eq!(
        report["checks"]["source_contract_annotation_drift"].as_str(),
        Some("fail")
    );
    assert_eq!(
        report["summary"]["untracked_contract_annotation_count"].as_u64(),
        Some(1)
    );
    assert!(
        report["newly_found_drift"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["file_path"]
                .as_str()
                .unwrap_or_default()
                .contains("new-drift"))
    );
}

#[test]
fn explicit_symbol_allowlist_turns_false_positive_into_allowed_drift() {
    let root = workspace_root();
    let source = unique_temp_path("semantic-contract-allowlisted.rs");
    std::fs::write(
        &source,
        "/// semantic contract: fallback wording in a generated test fixture only\npub fn fixture_only() {}\n",
    )
    .expect("failed to write allowlisted source fixture");

    let artifact_path = unique_temp_path("semantic-contract-allowlisted-artifact.json");
    let mut artifact =
        load_json(&root.join("tests/conformance/semantic_contract_drift_scan.v1.json"));
    artifact["source_scan_roots"] = serde_json::json!([source]);
    artifact["source_scan_suffixes"] = serde_json::json!([]);
    artifact["intentional_false_positive_allowlist"] = serde_json::json!([
        {
            "symbol": "fixture_only",
            "file_path": format!("*{}", source.file_name().unwrap().to_string_lossy()),
            "pattern": "generated test fixture only",
            "contract_class": "deterministic_fallback",
            "evidence_reason": "Temporary replay fixture exercises allowlist logic and is not an exported ABI contract."
        }
    ]);
    std::fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap() + "\n",
    )
    .expect("failed to write allowlisted artifact fixture");

    let output = run_gate_with_env(&[("FLC_SEMANTIC_DRIFT_ARTIFACT", &artifact_path)]);
    assert!(
        output.status.success(),
        "allowlisted false positive should pass:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report = parse_stdout_report(&output);
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(
        report["summary"]["allowed_false_positive_count"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["summary"]["untracked_contract_annotation_count"].as_u64(),
        Some(0)
    );
    let allowed = report["allowed_drift"].as_array().unwrap();
    assert_eq!(allowed[0]["symbol"].as_str(), Some("fixture_only"));
    assert!(
        allowed[0]["evidence_reason"]
            .as_str()
            .unwrap()
            .contains("replay fixture")
    );
}
