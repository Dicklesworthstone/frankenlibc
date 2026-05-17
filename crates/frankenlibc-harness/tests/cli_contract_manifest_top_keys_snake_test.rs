//! Meta-gate: every top-level key in every `*_cli_contract.v1.json`
//! manifest is a lowercase snake_case identifier (bd-h4avv). Catches
//! PascalCase / camelCase / kebab-case drift in top-level field names.

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
fn every_cli_contract_top_level_key_is_snake_case() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_keys = 0usize;
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
        for k in o.keys() {
            checked_keys += 1;
            if !is_snake_case_identifier(k) {
                violations.push(format!("{name}: top-level key `{k}` is not snake_case"));
            }
        }
    }

    assert!(
        checked_keys >= 500,
        "expected at least 500 top-level keys; found {checked_keys}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} top-level key snake_case violation(s) across {checked_keys} keys:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
