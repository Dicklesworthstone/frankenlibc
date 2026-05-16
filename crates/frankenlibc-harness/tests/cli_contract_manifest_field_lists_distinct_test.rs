//! Meta-gate: field-list arrays inside `tests/conformance/*_cli_contract.v1.json`
//! manifests must not duplicate entries (bd-2yx2k). This catches inflated
//! JSON/JSONL field coverage claims where a contract repeats a required field
//! without adding real output-shape coverage.

use std::collections::HashSet;
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

fn is_field_list_key(key: &str) -> bool {
    key == "required_fields"
        || key.contains("required_fields")
        || key.ends_with("_fields")
        || key.ends_with("_field_markers")
}

fn walk_field_lists(
    stem: &str,
    value: &Value,
    path: &mut Vec<String>,
    checked: &mut usize,
    violations: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                path.push(key.clone());
                if is_field_list_key(key)
                    && let Value::Array(entries) = child
                {
                    let mut seen: HashSet<&str> = HashSet::new();
                    let mut string_entries = 0usize;
                    for entry in entries {
                        if let Some(field) = entry.as_str() {
                            string_entries += 1;
                            if !seen.insert(field) {
                                violations.push(format!(
                                    "{stem}: {} duplicates `{field}`",
                                    path.join(".")
                                ));
                            }
                        }
                    }
                    if string_entries > 0 {
                        *checked += 1;
                    }
                }
                walk_field_lists(stem, child, path, checked, violations);
                path.pop();
            }
        }
        Value::Array(entries) => {
            for (index, child) in entries.iter().enumerate() {
                path.push(index.to_string());
                walk_field_lists(stem, child, path, checked, violations);
                path.pop();
            }
        }
        _ => {}
    }
}

#[test]
fn cli_contract_field_lists_have_distinct_entries() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|error| format!("read_dir {conformance_dir:?}: {error}"))?;

    let mut checked = 0usize;
    let mut violations: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read entry: {error}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }

        let body =
            std::fs::read_to_string(&path).map_err(|error| format!("read {path:?}: {error}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|error| format!("parse {path:?}: {error}"))?;
        walk_field_lists(
            stem,
            &manifest,
            &mut Vec::new(),
            &mut checked,
            &mut violations,
        );
    }

    assert!(
        checked >= 80,
        "expected at least 80 CLI contract field-list arrays; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract field-list duplicate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
