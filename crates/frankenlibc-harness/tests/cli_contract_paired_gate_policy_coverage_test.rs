//! Meta-gate: every policy invariant declared by a
//! `tests/conformance/*_cli_contract.v1.json` manifest must be named by
//! its paired `crates/frankenlibc-harness/tests/*_cli_contract_test.rs`
//! gate (bd-tx0c5). This catches manifest-only policy drift where a new
//! invariant is added to the contract but the executable gate never pins it.

use std::path::{Path, PathBuf};

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

fn paired_gate_test_name(manifest_name: &str) -> TestResult<String> {
    manifest_name
        .strip_suffix(".v1.json")
        .map(|stem| format!("{stem}_test.rs"))
        .ok_or_else(|| format!("{manifest_name}: expected .v1.json suffix"))
}

fn quoted_policy_key(key: &str) -> String {
    format!("\"{key}\"")
}

#[test]
fn every_manifest_policy_key_is_named_by_paired_gate() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_manifests = 0usize;
    let mut checked_policy_keys = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }

        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(policy) = manifest.get("policy").and_then(Value::as_object) else {
            continue;
        };

        let test_name = paired_gate_test_name(name)?;
        let test_path = tests_dir.join(&test_name);
        let test_body = match std::fs::read_to_string(&test_path) {
            Ok(body) => body,
            Err(error) => {
                violations.push(format!(
                    "{name}: paired gate `{test_name}` is unreadable: {error}"
                ));
                checked_manifests += 1;
                continue;
            }
        };

        for key in policy.keys() {
            checked_policy_keys += 1;
            let quoted = quoted_policy_key(key);
            if !test_body.contains(&quoted) {
                violations.push(format!(
                    "{name}: policy key `{key}` is not named as {quoted} in paired gate `{test_name}`"
                ));
            }
        }
        checked_manifests += 1;
    }

    assert!(
        checked_manifests >= 60,
        "expected at least 60 cli_contract manifests; found {checked_manifests}"
    );
    assert!(
        checked_policy_keys >= 300,
        "expected at least 300 manifest policy keys; found {checked_policy_keys}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate policy-coverage violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn paired_gate_test_name_maps_cli_contract_manifest_name() -> TestResult {
    assert_eq!(
        paired_gate_test_name("kernel_regression_report_cli_contract.v1.json")?,
        "kernel_regression_report_cli_contract_test.rs"
    );
    assert!(paired_gate_test_name("kernel_regression_report_cli_contract.json").is_err());
    Ok(())
}

#[test]
fn quoted_policy_key_matches_literal_rust_string_form() {
    assert_eq!(
        quoted_policy_key("must_emit_exactly_one_jsonl_record"),
        "\"must_emit_exactly_one_jsonl_record\""
    );
}
