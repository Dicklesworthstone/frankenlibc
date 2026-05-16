//! Meta-gate: when a `tests/conformance/*_cli_contract.v1.json` manifest's
//! `summary.report_only` field is present, it must be a bool (bd-pzito).
//! Catches type drift (string "true", numeric 1, etc.) that would defeat
//! downstream readers.

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

fn classify(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[test]
fn summary_report_only_when_present_is_bool_typed() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut declared = 0usize;
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
        let Some(summary) = manifest.get("summary") else {
            continue;
        };
        let Some(report_only) = summary.get("report_only") else {
            continue;
        };
        if !report_only.is_boolean() {
            violations.push(format!(
                "{stem}: summary.report_only must be a bool (got {})",
                classify(report_only)
            ));
        }
        declared += 1;
    }

    assert!(
        declared >= 10,
        "expected at least 10 manifests with summary.report_only; found {declared}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} summary.report_only type violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
