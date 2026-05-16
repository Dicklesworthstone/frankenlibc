//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare `required_flags` and `optional_flags` as JSON arrays of strings
//! starting with `--`, unique within each list, and disjoint across the
//! required/optional split (bd-1igth, bd-e3oco, bd-h65ta). It also requires
//! `source_commit` to be either an 8-hex short SHA or a 40-hex full SHA.
//! Catches schema drift where a manifest emits a wrong type, a flag name
//! without the long-form `--` prefix, duplicates a flag declaration, omits the
//! split between required and optional flags, or uses a placeholder-style source
//! commit.

use std::collections::BTreeSet;
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

fn validate_flag_array(
    manifest: &Value,
    field: &str,
    stem: &str,
    violations: &mut Vec<String>,
) -> Vec<String> {
    let Some(value) = manifest.get(field) else {
        violations.push(format!("{stem}: `{field}` missing"));
        return Vec::new();
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
        return Vec::new();
    };
    let mut flags = Vec::new();
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
        flags.push(s.to_string());
    }
    flags
}

fn validate_flag_uniqueness(
    required_flags: &[String],
    optional_flags: &[String],
    stem: &str,
    violations: &mut Vec<String>,
) {
    let mut required_seen = BTreeSet::new();
    for flag in required_flags {
        if !required_seen.insert(flag.as_str()) {
            violations.push(format!("{stem}: `required_flags` duplicates `{flag}`"));
        }
    }

    let mut optional_seen = BTreeSet::new();
    for flag in optional_flags {
        if !optional_seen.insert(flag.as_str()) {
            violations.push(format!("{stem}: `optional_flags` duplicates `{flag}`"));
        }
    }

    for flag in required_seen.intersection(&optional_seen) {
        violations.push(format!(
            "{stem}: flag `{flag}` appears in both `required_flags` and `optional_flags`"
        ));
    }
}

fn is_short_or_full_lower_hex_sha(value: &str) -> bool {
    matches!(value.len(), 8 | 40)
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn flag_arrays_are_declared_well_typed_unique_and_disjoint() -> TestResult {
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
        let required_flags =
            validate_flag_array(&manifest, "required_flags", stem, &mut violations);
        let optional_flags =
            validate_flag_array(&manifest, "optional_flags", stem, &mut violations);
        validate_flag_uniqueness(&required_flags, &optional_flags, stem, &mut violations);
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

#[test]
fn source_commit_is_short_or_full_lower_hex_sha() -> TestResult {
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
        match manifest.get("source_commit") {
            Some(Value::String(commit)) if is_short_or_full_lower_hex_sha(commit) => {}
            Some(Value::String(commit)) => violations.push(format!(
                "{stem}: `source_commit`=`{commit}` must be 8 or 40 lowercase hex chars"
            )),
            Some(other) => violations.push(format!(
                "{stem}: `source_commit` must be a string (got {})",
                match other {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                }
            )),
            None => violations.push(format!("{stem}: `source_commit` missing")),
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract source_commit shape violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
