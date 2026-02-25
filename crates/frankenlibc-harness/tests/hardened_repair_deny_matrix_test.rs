//! Integration test: Hardened repair/deny completeness matrix (bd-w2c3.3.2)
//!
//! Validates:
//! 1. Matrix artifact exists with required schema fields.
//! 2. Declared invalid-input classes are fully covered by entries.
//! 3. fixture_case_refs resolve to hardened fixture cases.
//! 4. Gate script exists, is executable, and passes.
//!
//! Run:
//!   cargo test -p frankenlibc-harness --test hardened_repair_deny_matrix_test

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn healing_action_variants_from_source(root: &Path) -> Vec<String> {
    let heal_source = std::fs::read_to_string(root.join("crates/frankenlibc-membrane/src/heal.rs"))
        .expect("heal.rs should be readable");
    let marker = "pub enum HealingAction";
    let start = heal_source
        .find(marker)
        .expect("HealingAction enum declaration should exist");
    let body_start = heal_source[start..]
        .find('{')
        .map(|offset| start + offset + 1)
        .expect("HealingAction enum should include opening brace");
    let body_end = heal_source[body_start..]
        .find('}')
        .map(|offset| body_start + offset)
        .expect("HealingAction enum should include closing brace");
    let body = &heal_source[body_start..body_end];
    let mut variants = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("///")
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
        {
            continue;
        }
        let name = trimmed
            .split('{')
            .next()
            .unwrap()
            .split('(')
            .next()
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .trim();
        if !name.is_empty() && name.as_bytes()[0].is_ascii_alphabetic() {
            variants.push(name.to_string());
        }
    }
    variants
}

#[test]
fn matrix_exists_and_summary_is_consistent() {
    let root = workspace_root();
    let matrix_path = root.join("tests/conformance/hardened_repair_deny_matrix.v1.json");
    let matrix = load_json(&matrix_path);

    assert_eq!(matrix["schema_version"].as_str(), Some("v1"));
    assert_eq!(matrix["bead"].as_str(), Some("bd-w2c3.3.2"));
    assert!(matrix["entries"].is_array(), "entries must be an array");
    assert!(
        matrix["invalid_input_classes"].is_array(),
        "invalid_input_classes must be an array"
    );
    assert!(
        matrix["known_healing_actions"].is_array(),
        "known_healing_actions must be an array"
    );

    let entries = matrix["entries"].as_array().unwrap();
    let classes = matrix["invalid_input_classes"].as_array().unwrap();
    let summary = matrix["summary"]
        .as_object()
        .expect("summary must be an object");

    assert!(!entries.is_empty(), "entries should not be empty");
    assert!(
        !classes.is_empty(),
        "invalid_input_classes should not be empty"
    );

    let declared: std::collections::HashSet<String> = classes
        .iter()
        .map(|row| {
            row["id"]
                .as_str()
                .expect("invalid_input_classes[].id must be string")
                .to_string()
        })
        .collect();
    let covered: std::collections::HashSet<String> = entries
        .iter()
        .map(|row| {
            row["invalid_input_class"]
                .as_str()
                .expect("entries[].invalid_input_class must be string")
                .to_string()
        })
        .collect();
    assert_eq!(declared, covered, "all declared classes must be covered");

    let repair_count = entries
        .iter()
        .filter(|row| row["decision_path"].as_str() == Some("Repair"))
        .count();
    let deny_count = entries
        .iter()
        .filter(|row| row["decision_path"].as_str() == Some("Deny"))
        .count();
    assert!(repair_count > 0, "matrix must include Repair entries");
    assert!(deny_count > 0, "matrix must include Deny entries");

    assert_eq!(
        summary
            .get("total_invalid_input_classes")
            .and_then(|v| v.as_u64()),
        Some(declared.len() as u64)
    );
    assert_eq!(
        summary
            .get("covered_invalid_input_classes")
            .and_then(|v| v.as_u64()),
        Some(covered.len() as u64)
    );
    assert_eq!(
        summary.get("entry_count").and_then(|v| v.as_u64()),
        Some(entries.len() as u64)
    );
    assert_eq!(
        summary.get("repair_entries").and_then(|v| v.as_u64()),
        Some(repair_count as u64)
    );
    assert_eq!(
        summary.get("deny_entries").and_then(|v| v.as_u64()),
        Some(deny_count as u64)
    );
}

#[test]
fn known_healing_actions_match_live_healing_action_enum() {
    let root = workspace_root();
    let matrix_path = root.join("tests/conformance/hardened_repair_deny_matrix.v1.json");
    let matrix = load_json(&matrix_path);
    let matrix_actions: std::collections::HashSet<String> = matrix["known_healing_actions"]
        .as_array()
        .expect("known_healing_actions must be array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("known_healing_actions[] must be string")
                .to_string()
        })
        .collect();
    let enum_actions: std::collections::HashSet<String> =
        healing_action_variants_from_source(&root)
            .into_iter()
            .collect();

    assert_eq!(
        matrix_actions, enum_actions,
        "matrix known_healing_actions must stay in sync with HealingAction enum variants"
    );
}

#[test]
fn fixture_refs_exist_and_are_hardened_cases() {
    let root = workspace_root();
    let matrix_path = root.join("tests/conformance/hardened_repair_deny_matrix.v1.json");
    let matrix = load_json(&matrix_path);
    let entries = matrix["entries"].as_array().unwrap();

    for row in entries {
        let entry_id = row["entry_id"].as_str().unwrap_or("<missing-entry-id>");
        let refs = row["fixture_case_refs"]
            .as_array()
            .expect("fixture_case_refs must be array");
        assert!(
            !refs.is_empty(),
            "{entry_id}: fixture_case_refs must be non-empty"
        );

        for ref_value in refs {
            let reference = ref_value
                .as_str()
                .expect("fixture_case_refs[] must be string");
            let (fixture_path, case_name) = reference
                .split_once("#/cases/")
                .expect("fixture_case_refs entry must use <path>#/cases/<name>");
            let fixture = load_json(&root.join(fixture_path));
            let cases = fixture["cases"]
                .as_array()
                .expect("fixture cases must be array");
            let case = cases
                .iter()
                .find(|candidate| candidate["name"].as_str() == Some(case_name))
                .unwrap_or_else(|| panic!("{entry_id}: missing referenced case {reference}"));
            assert_eq!(
                case["mode"].as_str(),
                Some("hardened"),
                "{entry_id}: fixture case must be hardened: {reference}"
            );
        }
    }
}

#[test]
fn gate_script_is_executable_and_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_hardened_repair_deny_matrix.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_hardened_repair_deny_matrix.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run hardened repair/deny gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let matrix_path = root.join("tests/conformance/hardened_repair_deny_matrix.v1.json");
    let matrix = load_json(&matrix_path);
    let matrix_summary = matrix["summary"]
        .as_object()
        .expect("matrix summary must be object");

    let report_path = root.join("target/conformance/hardened_repair_deny_matrix.report.json");
    assert!(
        report_path.exists(),
        "gate script must emit report artifact at {}",
        report_path.display()
    );
    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-249m.2"));
    assert_eq!(report["source_matrix_bead"].as_str(), Some("bd-w2c3.3.2"));
    assert_eq!(
        report["summary"]["entry_count"].as_u64(),
        matrix_summary
            .get("entry_count")
            .and_then(serde_json::Value::as_u64)
    );
    assert_eq!(
        report["summary"]["repair_entries"].as_u64(),
        matrix_summary
            .get("repair_entries")
            .and_then(serde_json::Value::as_u64)
    );
    assert_eq!(
        report["summary"]["deny_entries"].as_u64(),
        matrix_summary
            .get("deny_entries")
            .and_then(serde_json::Value::as_u64)
    );
    let mapping_hash = report["summary"]["policy_mapping_sha256"]
        .as_str()
        .expect("report summary must include policy_mapping_sha256");
    assert_eq!(
        mapping_hash.len(),
        64,
        "policy_mapping_sha256 must be a 64-char hex digest"
    );

    let log_path = root.join("target/conformance/hardened_repair_deny_matrix.log.jsonl");
    assert!(
        log_path.exists(),
        "gate script must emit log artifact at {}",
        log_path.display()
    );
    let log_contents = std::fs::read_to_string(&log_path).expect("log jsonl should be readable");
    let log_line = log_contents
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("log jsonl must contain at least one line");
    let event: serde_json::Value =
        serde_json::from_str(log_line).expect("log line must be valid json");
    assert_eq!(
        event["policy_mapping_sha256"].as_str(),
        Some(mapping_hash),
        "log event hash must match report hash"
    );
    let artifact_refs = event["artifact_refs"]
        .as_array()
        .expect("log event artifact_refs must be array");
    assert!(
        artifact_refs
            .iter()
            .any(|value| value.as_str() == Some(report_path.to_string_lossy().as_ref())),
        "log event must reference the generated report artifact"
    );
}

#[test]
fn policy_mapping_is_deterministic_across_reloads() {
    let root = workspace_root();
    let matrix_path = root.join("tests/conformance/hardened_repair_deny_matrix.v1.json");

    let canonical_mapping = |matrix: &serde_json::Value| -> Vec<String> {
        let mut rows = matrix["entries"]
            .as_array()
            .expect("entries must be array")
            .iter()
            .map(|entry| {
                format!(
                    "{}|{}|{}|{}|{}|{}",
                    entry["policy_id"]
                        .as_str()
                        .expect("policy_id must be string"),
                    entry["decision_path"]
                        .as_str()
                        .expect("decision_path must be string"),
                    entry["healing_action"]
                        .as_str()
                        .expect("healing_action must be string"),
                    entry["api_family"]
                        .as_str()
                        .expect("api_family must be string"),
                    entry["symbol"].as_str().expect("symbol must be string"),
                    entry["invalid_input_class"]
                        .as_str()
                        .expect("invalid_input_class must be string")
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    };

    let baseline = canonical_mapping(&load_json(&matrix_path));
    assert!(!baseline.is_empty(), "matrix entries should not be empty");

    for _ in 0..1000 {
        let matrix = load_json(&matrix_path);
        let observed = canonical_mapping(&matrix);
        assert_eq!(
            observed, baseline,
            "policy/action mapping changed between reloads"
        );
    }
}
