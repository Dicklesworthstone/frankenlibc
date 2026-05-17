//! Meta-gate: every key inside a `summary` object across all
//! `*_cli_contract.v1.json` manifests is a lowercase snake_case
//! identifier (bd-rfi5u). Catches PascalCase / camelCase /
//! kebab-case drift in summary field names.

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
fn every_cli_contract_summary_object_key_is_snake_case() -> TestResult {
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
        let Some(Value::Object(summary)) = manifest.get("summary") else {
            continue;
        };
        for k in summary.keys() {
            checked_keys += 1;
            if !is_snake_case_identifier(k) {
                violations.push(format!("{name}: summary key `{k}` is not snake_case"));
            }
        }
    }

    assert!(
        checked_keys >= 50,
        "expected at least 50 summary keys; found {checked_keys}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} summary-key snake_case violation(s) across {checked_keys} keys:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
