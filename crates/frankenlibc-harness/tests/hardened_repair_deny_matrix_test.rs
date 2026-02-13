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
    let summary = matrix["summary"].as_object().expect("summary must be an object");

    assert!(!entries.is_empty(), "entries should not be empty");
    assert!(!classes.is_empty(), "invalid_input_classes should not be empty");

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
        summary.get("total_invalid_input_classes").and_then(|v| v.as_u64()),
        Some(declared.len() as u64)
    );
    assert_eq!(
        summary.get("covered_invalid_input_classes").and_then(|v| v.as_u64()),
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
            let cases = fixture["cases"].as_array().expect("fixture cases must be array");
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
}
