//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares an
//! `output_contract` object (alternative to `jsonl_output_contract`
//! for non-JSONL outputs), it must be a non-empty object (bd-a2p9r).
//! Catches stub manifests that ship `output_contract: {}` placeholders.

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

#[test]
fn every_cli_contract_output_contract_is_non_empty_object_when_present() -> TestResult {
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
        let Some(oc) = manifest.get("output_contract") else {
            continue;
        };
        checked += 1;
        match oc {
            Value::Object(o) if o.is_empty() => {
                violations.push(format!("{name}: `output_contract` is empty object"))
            }
            Value::Object(_) => {}
            other => violations.push(format!(
                "{name}: `output_contract` is not an object (found {})",
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

    assert!(
        checked >= 5,
        "expected at least 5 cli_contract manifests with output_contract; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} output_contract non-empty violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
