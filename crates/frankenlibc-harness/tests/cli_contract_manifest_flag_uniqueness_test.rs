//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `required_flags` and `optional_flags` arrays have no duplicate
//! entries (bd-pq6z5 for required, bd-lyztc covers optional via the
//! same gate). Catches accidental copy-paste duplication during
//! manifest authoring.

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

fn duplicates_in_string_array(arr: &[Value]) -> Vec<String> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut dupes: Vec<String> = Vec::new();
    for v in arr {
        let Some(s) = v.as_str() else { continue };
        if !seen.insert(s) {
            dupes.push(s.to_string());
        }
    }
    dupes
}

#[test]
fn every_cli_contract_required_flags_array_has_no_duplicates() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
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
        let Some(Value::Array(arr)) = manifest.get("required_flags") else {
            continue;
        };
        let dupes = duplicates_in_string_array(arr);
        if !dupes.is_empty() {
            violations.push(format!(
                "{name}: required_flags has {} duplicate entrie(s): {dupes:?}",
                dupes.len()
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
            "{} required_flags duplicate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn every_cli_contract_optional_flags_array_has_no_duplicates() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
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
        let dupes = duplicates_in_string_array(arr);
        if !dupes.is_empty() {
            violations.push(format!(
                "{name}: optional_flags has {} duplicate entrie(s): {dupes:?}",
                dupes.len()
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
            "{} optional_flags duplicate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn duplicate_detector_handles_canonical_forms() {
    use serde_json::json;
    assert!(duplicates_in_string_array(&[json!("--a"), json!("--b")]).is_empty());
    let arr = vec![json!("--a"), json!("--b"), json!("--a")];
    let dupes = duplicates_in_string_array(&arr);
    assert_eq!(dupes, vec!["--a".to_string()]);
}
