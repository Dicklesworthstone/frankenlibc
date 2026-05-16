//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares
//! `jsonl_output_contract`, its `record_count` field must be either a
//! positive integer or a non-empty string expression with a digit
//! (e.g. `"R+1"`, `"N+1"`) (bd-eygve). Catches stub manifests with
//! `record_count: 0`, missing field, or empty placeholder string.

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

fn is_valid_record_count(v: &Value) -> Result<(), String> {
    match v {
        Value::Number(n) => match n.as_u64() {
            Some(k) if k >= 1 => Ok(()),
            Some(0) => Err("record_count is 0 (stub)".to_string()),
            _ => Err(format!(
                "record_count number `{n}` is not a positive integer"
            )),
        },
        Value::String(s) if s.is_empty() => Err("record_count is empty string".to_string()),
        Value::String(s) if !s.chars().any(|c| c.is_ascii_digit()) => Err(format!(
            "record_count string `{s}` contains no digit (expected expression like `R+1`)"
        )),
        Value::String(_) => Ok(()),
        other => Err(format!(
            "record_count is {} (expected positive integer or non-empty string)",
            match other {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            }
        )),
    }
}

#[test]
fn cli_contract_manifest_jsonl_record_count_is_well_formed() -> TestResult {
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
        let Some(jsonl_contract) = manifest.get("jsonl_output_contract") else {
            continue;
        };
        match jsonl_contract.get("record_count") {
            None => violations.push(format!(
                "{name}: jsonl_output_contract has no `record_count` field"
            )),
            Some(v) => {
                if let Err(msg) = is_valid_record_count(v) {
                    violations.push(format!("{name}: {msg}"));
                }
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 10,
        "expected at least 10 jsonl_output_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl record_count violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn record_count_validator_handles_canonical_forms() {
    assert!(is_valid_record_count(&Value::from(1u64)).is_ok());
    assert!(is_valid_record_count(&Value::from(42u64)).is_ok());
    assert!(is_valid_record_count(&Value::from("R+1")).is_ok());
    assert!(is_valid_record_count(&Value::from("N+1")).is_ok());
    assert!(is_valid_record_count(&Value::from(0u64)).is_err());
    assert!(is_valid_record_count(&Value::from("")).is_err());
    assert!(is_valid_record_count(&Value::from("TODO")).is_err());
    assert!(is_valid_record_count(&Value::Null).is_err());
}
