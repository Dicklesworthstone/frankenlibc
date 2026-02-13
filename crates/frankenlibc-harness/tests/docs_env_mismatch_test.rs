//! Integration test: docs env mismatch classification gate (bd-29b.2)
//!
//! Validates that:
//! 1. Docs inventory and mismatch report files exist and are valid JSON.
//! 2. Every mismatch row is fully classified with remediation action.
//! 3. unresolved_ambiguous list is empty.
//! 4. Gate script exists, is executable, and passes.

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
    let content = std::fs::read_to_string(path).expect("json file should exist");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn docs_inventory_exists_and_has_expected_shape() {
    let root = workspace_root();
    let docs_inventory = load_json(&root.join("tests/conformance/docs_env_inventory.v1.json"));
    assert_eq!(
        docs_inventory["schema_version"].as_str(),
        Some("v1"),
        "docs inventory schema_version must be v1"
    );
    assert!(
        docs_inventory["docs_files"].is_array(),
        "docs_files must be array"
    );
    assert!(docs_inventory["keys"].is_array(), "keys must be array");
    assert!(
        docs_inventory["summary"].is_object(),
        "summary must be object"
    );
}

#[test]
fn mismatch_report_is_fully_classified() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/env_docs_code_mismatch_report.v1.json"));

    assert_eq!(
        report["schema_version"].as_str(),
        Some("v1"),
        "mismatch report schema_version must be v1"
    );

    let classes = report["classifications"]
        .as_array()
        .expect("classifications must be array");
    for row in classes {
        let key = row["env_key"].as_str().unwrap_or("<unknown>");
        let class = row["mismatch_class"].as_str().unwrap_or("");
        assert!(
            matches!(
                class,
                "missing_in_docs" | "missing_in_code" | "semantic_drift"
            ),
            "{key}: invalid mismatch_class '{class}'"
        );
        assert!(
            row["remediation_action"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "{key}: remediation_action must be non-empty"
        );
        assert!(row["details"].is_string(), "{key}: details must be string");
        assert!(row["evidence"].is_array(), "{key}: evidence must be array");
    }
}

#[test]
fn mismatch_summary_counts_are_zero() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/env_docs_code_mismatch_report.v1.json"));
    let summary = report["summary"]
        .as_object()
        .expect("summary must be object");

    for key in [
        "missing_in_docs_count",
        "missing_in_code_count",
        "semantic_drift_count",
    ] {
        let value = summary
            .get(key)
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX);
        assert_eq!(value, 0, "{key} must be zero, got {value}");
    }
}

#[test]
fn unresolved_ambiguous_is_empty() {
    let root = workspace_root();
    let report = load_json(&root.join("tests/conformance/env_docs_code_mismatch_report.v1.json"));
    let unresolved = report["unresolved_ambiguous"]
        .as_array()
        .expect("unresolved_ambiguous must be array");
    assert!(
        unresolved.is_empty(),
        "unresolved_ambiguous must be empty, got: {unresolved:?}"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_env_mismatch.sh");
    assert!(
        script.exists(),
        "scripts/check_docs_env_mismatch.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_docs_env_mismatch.sh must be executable"
        );
    }
}

#[test]
fn gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_docs_env_mismatch.sh");
    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("check_docs_env_mismatch.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "check_docs_env_mismatch.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}
