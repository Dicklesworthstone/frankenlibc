//! Meta-gate: no entry in any `jsonl_output_contract.required_fields`
//! array starts with `_` (bd-tzcjt). Leading-underscore field names
//! are conventionally private/internal in JSON consumers and should
//! never appear in a public output contract.

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
fn no_cli_contract_required_fields_entry_starts_with_underscore() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_entries = 0usize;
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
        let Some(Value::Array(arr)) = manifest
            .get("jsonl_output_contract")
            .and_then(|j| j.get("required_fields"))
        else {
            continue;
        };
        for (i, v) in arr.iter().enumerate() {
            let Some(s) = v.as_str() else {
                continue;
            };
            checked_entries += 1;
            if s.starts_with('_') {
                violations.push(format!(
                    "{name}: jsonl_output_contract.required_fields[{i}] = `{s}` starts with underscore (private fields don't belong in output contracts)"
                ));
            }
        }
    }

    assert!(
        checked_entries >= 50,
        "expected at least 50 required_fields entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} required_fields leading-underscore violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
