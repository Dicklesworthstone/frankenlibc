//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` keeps `required_flags` at 20 entries or fewer
//! (bd-5wyz2). This catches accidental flag-list explosions or duplicated
//! required flag declarations before a manifest becomes unreadable.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MAX_REQUIRED_FLAGS: usize = 20;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn value_kind(value: &Value) -> &'static str {
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
fn every_cli_contract_manifest_required_flags_within_count_ceiling() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut largest_count = 0usize;
    let mut largest_name = String::new();
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
        let Some(required_flags) = manifest.get("required_flags") else {
            violations.push(format!("{name}: missing `required_flags` array"));
            checked += 1;
            continue;
        };
        let Some(required_flags) = required_flags.as_array() else {
            violations.push(format!(
                "{name}: `required_flags` is {} (expected array)",
                value_kind(required_flags)
            ));
            checked += 1;
            continue;
        };

        let count = required_flags.len();
        if count > largest_count {
            largest_count = count;
            largest_name = name.to_string();
        }
        if count > MAX_REQUIRED_FLAGS {
            violations.push(format!(
                "{name}: required_flags has {count} entrie(s); ceiling is {MAX_REQUIRED_FLAGS}"
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
            "{} cli_contract manifest required_flags-count violation(s) (ceiling={MAX_REQUIRED_FLAGS}, largest seen={largest_name} @ {largest_count}):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
