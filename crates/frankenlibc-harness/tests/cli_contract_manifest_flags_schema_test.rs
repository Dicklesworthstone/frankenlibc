//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare `required_flags` (if present) and `optional_flags` (if present) as
//! JSON arrays of strings starting with `--` (bd-1igth). Catches schema drift
//! where a manifest emits a wrong type or a flag name without the long-form
//! `--` prefix.

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

fn validate_flag_array(manifest: &Value, field: &str, stem: &str, violations: &mut Vec<String>) {
    let Some(value) = manifest.get(field) else {
        return;
    };
    let Some(arr) = value.as_array() else {
        violations.push(format!(
            "{stem}: `{field}` must be a JSON array (got {})",
            match value {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            }
        ));
        return;
    };
    for (i, entry) in arr.iter().enumerate() {
        let Some(s) = entry.as_str() else {
            violations.push(format!(
                "{stem}: `{field}[{i}]` must be a string (got {entry:?})"
            ));
            continue;
        };
        if !s.starts_with("--") {
            violations.push(format!("{stem}: `{field}[{i}]`=`{s}` must start with `--`"));
        }
    }
}

#[test]
fn flag_arrays_have_well_typed_entries_starting_with_double_dash() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))?;
        validate_flag_array(&manifest, "required_flags", stem, &mut violations);
        validate_flag_array(&manifest, "optional_flags", stem, &mut violations);
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract flag schema violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
