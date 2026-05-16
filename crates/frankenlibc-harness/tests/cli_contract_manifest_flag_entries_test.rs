//! Meta-gate: every entry in `required_flags` / `optional_flags` of
//! every `*_cli_contract.v1.json` manifest under `tests/conformance/`
//! is a non-empty string starting with `-` or `--` followed by a
//! lowercase ASCII letter (bd-ptrn6). Catches stub flag entries
//! (empty strings, hexdumps, accidental object form, or missing
//! leading dashes).

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

fn looks_like_cli_flag(s: &str) -> bool {
    // Either `-x...` or `--x...` where x is a lowercase ASCII letter.
    let stripped = match s.strip_prefix("--") {
        Some(rest) => rest,
        None => match s.strip_prefix('-') {
            Some(rest) => rest,
            None => return false,
        },
    };
    matches!(stripped.chars().next(), Some(c) if c.is_ascii_lowercase())
}

#[test]
fn every_cli_contract_manifest_flag_entries_look_like_cli_flags() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_manifests = 0usize;
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
        for field in ["required_flags", "optional_flags"] {
            let Some(Value::Array(arr)) = manifest.get(field) else {
                continue;
            };
            for (i, v) in arr.iter().enumerate() {
                checked_entries += 1;
                match v.as_str() {
                    None => violations.push(format!(
                        "{name}: {field}[{i}] is not a string (found {})",
                        match v {
                            Value::Null => "null",
                            Value::Bool(_) => "bool",
                            Value::Number(_) => "number",
                            Value::String(_) => "string",
                            Value::Array(_) => "array",
                            Value::Object(_) => "object",
                        }
                    )),
                    Some(s) if !looks_like_cli_flag(s) => violations.push(format!(
                        "{name}: {field}[{i}] = `{s}` is not a CLI flag (need `-x` or `--x`)"
                    )),
                    Some(_) => {}
                }
            }
        }
        checked_manifests += 1;
    }

    assert!(
        checked_manifests >= 30,
        "expected at least 30 cli_contract manifests; found {checked_manifests}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} flag-entry violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn cli_flag_validator_handles_canonical_forms() {
    assert!(looks_like_cli_flag("-x"));
    assert!(looks_like_cli_flag("--foo"));
    assert!(looks_like_cli_flag("--foo-bar"));
    assert!(looks_like_cli_flag("-a"));
    assert!(!looks_like_cli_flag(""));
    assert!(!looks_like_cli_flag("-"));
    assert!(!looks_like_cli_flag("--"));
    assert!(!looks_like_cli_flag("-X"));
    assert!(!looks_like_cli_flag("--X"));
    assert!(!looks_like_cli_flag("--1abc"));
    assert!(!looks_like_cli_flag("foo"));
    assert!(!looks_like_cli_flag("---foo"));
}
