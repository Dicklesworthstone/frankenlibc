//! Integration test: FEATURE_PARITY gap ledger extractor (bd-w2c3.1.1)
//!
//! Validates that:
//! 1. Gap ledger artifact exists and has expected schema.
//! 2. Row IDs are stable-format + unique and parser errors are empty.
//! 3. Generator self-tests pass (malformed rows / duplicates / status transitions).
//! 4. Gate script is executable and succeeds.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

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
fn artifact_exists_and_valid() {
    let root = workspace_root();
    let path = root.join("tests/conformance/feature_parity_gap_ledger.v1.json");
    let doc = load_json(&path);

    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-w2c3.1.1"));
    assert!(doc["rows"].is_array());
    assert!(doc["deltas"].is_array());
    assert!(doc["gaps"].is_array());
    assert!(doc["summary"].is_object());
}

#[test]
fn row_ids_are_unique_and_parser_errors_empty() {
    let root = workspace_root();
    let path = root.join("tests/conformance/feature_parity_gap_ledger.v1.json");
    let doc = load_json(&path);

    let rows = doc["rows"].as_array().unwrap();
    let parse_errors = doc["parse_errors"].as_array().unwrap();
    assert!(
        parse_errors.is_empty(),
        "parse_errors must be empty for canonical artifact"
    );
    assert!(!rows.is_empty(), "rows must be non-empty");

    let mut seen = HashSet::new();
    for row in rows {
        let row_id = row["row_id"].as_str().expect("row_id must be string");
        assert!(row_id.starts_with("fp-"), "row_id must use fp-* prefix");
        assert!(
            seen.insert(row_id.to_string()),
            "row_id must be unique, duplicate={row_id}"
        );
        assert!(
            row["provenance"]["path"].as_str().is_some(),
            "row must include provenance.path"
        );
        assert!(
            row["provenance"]["line"].as_u64().is_some(),
            "row must include provenance.line"
        );
    }
}

#[test]
fn generator_self_tests_pass() {
    let root = workspace_root();
    let script = root.join("scripts/generate_feature_parity_gap_ledger.py");

    let output = std::process::Command::new("python3")
        .arg(&script)
        .arg("--self-test")
        .current_dir(&root)
        .output()
        .expect("failed to run feature parity generator self-tests");

    assert!(
        output.status.success(),
        "generator self-tests failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_script_exists_and_succeeds() {
    let root = workspace_root();
    let script = root.join("scripts/check_feature_parity_gap_ledger.sh");
    assert!(
        script.exists(),
        "scripts/check_feature_parity_gap_ledger.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_feature_parity_gap_ledger.sh must be executable"
        );
    }

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run feature parity gap ledger gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
