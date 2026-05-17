//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares
//! `jsonl_output_contract`, the value is a JSON object — not a
//! string, array, or other shape (bd-j5bs4). Catches schema-shape
//! drift where the contract is accidentally encoded as a stringified
//! JSON blob or a flat array of field names.

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

fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[test]
fn every_cli_contract_jsonl_output_contract_is_object() -> TestResult {
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
        let Some(jsonl) = manifest.get("jsonl_output_contract") else {
            continue;
        };
        checked += 1;
        if !matches!(jsonl, Value::Object(_)) {
            violations.push(format!(
                "{name}: jsonl_output_contract is {} (expected object)",
                value_kind(jsonl)
            ));
        }
    }

    assert!(
        checked >= 20,
        "expected at least 20 jsonl_output_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl_output_contract shape violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
