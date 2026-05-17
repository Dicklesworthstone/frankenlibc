//! Meta-gate: no `*_cli_contract.v1.json` manifest contains a JSON
//! string value matching the literal `"TODO"` (bd-jtfiv). Catches
//! placeholder string values left behind from template scaffolding.
//! Recursively walks all string leaves in the manifest.

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

fn contains_todo_string(v: &Value) -> bool {
    match v {
        Value::String(s) => s == "TODO",
        Value::Array(arr) => arr.iter().any(contains_todo_string),
        Value::Object(o) => o.values().any(contains_todo_string),
        _ => false,
    }
}

#[test]
fn no_cli_contract_manifest_string_value_equals_todo() -> TestResult {
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
        if contains_todo_string(&manifest) {
            violations.push(format!("{name}: contains `\"TODO\"` string value"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} `\"TODO\"` string violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn todo_finder_handles_canonical_forms() {
    assert!(!contains_todo_string(&Value::String("done".into())));
    assert!(contains_todo_string(&Value::String("TODO".into())));
    assert!(!contains_todo_string(&Value::String(
        "TODO write more".into()
    )));
    let nested = serde_json::json!({"a": {"b": ["x", "TODO"]}});
    assert!(contains_todo_string(&nested));
}
