//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares
//! `jsonl_output_contract.required_fields`, every entry is a
//! lowercase snake_case identifier matching `^[a-z][a-z0-9_]*$`
//! (bd-3fta3). Catches PascalCase / camelCase / kebab-case drift in
//! per-record field names.

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

fn is_snake_case_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_jsonl_required_fields_entry_is_snake_case() -> TestResult {
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
            checked_entries += 1;
            match v.as_str() {
                Some(s) if is_snake_case_identifier(s) => {}
                Some(other) => violations.push(format!(
                    "{name}: jsonl_output_contract.required_fields[{i}] = `{other}` is not snake_case"
                )),
                None => violations.push(format!(
                    "{name}: jsonl_output_contract.required_fields[{i}] is not a string"
                )),
            }
        }
    }

    assert!(
        checked_entries >= 50,
        "expected at least 50 required_fields entries across manifests; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} required_fields snake_case violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_identifier_validator_handles_canonical_forms() {
    assert!(is_snake_case_identifier("foo"));
    assert!(is_snake_case_identifier("foo_bar"));
    assert!(is_snake_case_identifier("a1_b2"));
    assert!(!is_snake_case_identifier(""));
    assert!(!is_snake_case_identifier("Foo"));
    assert!(!is_snake_case_identifier("fooBar"));
    assert!(!is_snake_case_identifier("foo-bar"));
    assert!(!is_snake_case_identifier("1foo"));
    assert!(!is_snake_case_identifier("_foo"));
}
