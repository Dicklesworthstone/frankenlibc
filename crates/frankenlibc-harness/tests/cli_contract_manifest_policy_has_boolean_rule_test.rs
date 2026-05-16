//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares a `policy` object containing at
//! least one boolean field (bd-gaslo). Policies enforce structural
//! rules via boolean assertions; a policy without any boolean rule
//! is a stub.

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

fn policy_has_boolean_rule(policy: &Value) -> bool {
    match policy {
        Value::Object(o) => o.values().any(|v| matches!(v, Value::Bool(_))),
        _ => false,
    }
}

#[test]
fn every_cli_contract_manifest_policy_has_at_least_one_boolean_rule() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
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
        let Some(policy) = manifest.get("policy") else {
            violations.push(format!("{name}: missing `policy` field"));
            checked += 1;
            continue;
        };
        if !policy_has_boolean_rule(policy) {
            violations.push(format!("{name}: `policy` has no boolean rule fields"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} policy-boolean-rule violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn policy_boolean_rule_detector_handles_canonical_forms() {
    let policy = serde_json::json!({"must_emit": true, "max_records": 10});
    assert!(policy_has_boolean_rule(&policy));
    let no_bool = serde_json::json!({"max_records": 10, "label": "foo"});
    assert!(!policy_has_boolean_rule(&no_bool));
    let empty = serde_json::json!({});
    assert!(!policy_has_boolean_rule(&empty));
    let not_object = serde_json::json!([true, false]);
    assert!(!policy_has_boolean_rule(&not_object));
}
