//! Meta-gate: no `*_cli_contract.v1.json` manifest has a top-level
//! field whose value is the empty object `{}` (bd-y4o57). An empty
//! top-level object is almost always a stub or a never-populated
//! placeholder; true "no value" should omit the field entirely.

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
fn no_cli_contract_manifest_top_level_value_is_empty_object() -> TestResult {
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
        let Some(o) = manifest.as_object() else {
            continue;
        };
        let empty_obj_keys: Vec<String> = o
            .iter()
            .filter(|(_, v)| matches!(v, Value::Object(m) if m.is_empty()))
            .map(|(k, _)| k.clone())
            .collect();
        if !empty_obj_keys.is_empty() {
            violations.push(format!(
                "{name}: top-level fields with empty-object value: {empty_obj_keys:?}"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} empty-top-level-object violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
