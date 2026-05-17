//! Meta-gate: every entry in `optional_flags` of every
//! `*_cli_contract.v1.json` manifest, after stripping its leading
//! `--` or `-`, contains only lowercase ASCII letters, digits, and
//! hyphens (bd-5ia74). Sibling to bd-0stuh's required_flags rule.

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

fn flag_body_is_lowercase_kebab(flag: &str) -> bool {
    let stripped = match flag.strip_prefix("--") {
        Some(rest) => rest,
        None => match flag.strip_prefix('-') {
            Some(rest) => rest,
            None => return false,
        },
    };
    if stripped.is_empty() {
        return false;
    }
    let mut chars = stripped.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[test]
fn every_cli_contract_optional_flag_body_is_lowercase_kebab() -> TestResult {
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
        let Some(Value::Array(arr)) = manifest.get("optional_flags") else {
            continue;
        };
        for (i, v) in arr.iter().enumerate() {
            let Some(s) = v.as_str() else {
                continue;
            };
            checked_entries += 1;
            if !flag_body_is_lowercase_kebab(s) {
                violations.push(format!(
                    "{name}: optional_flags[{i}] = `{s}` body is not lowercase-kebab"
                ));
            }
        }
    }

    assert!(
        checked_entries >= 30,
        "expected at least 30 optional_flags entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} optional_flags lowercase-kebab violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
