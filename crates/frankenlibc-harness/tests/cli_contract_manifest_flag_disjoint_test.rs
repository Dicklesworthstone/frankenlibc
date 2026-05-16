//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `required_flags` and `optional_flags` arrays are disjoint — no
//! flag appears in both lists (bd-rx296). Catches manifests where a
//! flag was added to one list without being removed from the other
//! during a required <-> optional reclassification.

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

fn collect_string_set(arr: &[Value]) -> HashSet<&str> {
    arr.iter().filter_map(Value::as_str).collect()
}

#[test]
fn every_cli_contract_required_and_optional_flags_are_disjoint() -> TestResult {
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
        let req = manifest
            .get("required_flags")
            .and_then(Value::as_array)
            .map(|a| collect_string_set(a))
            .unwrap_or_default();
        let opt = manifest
            .get("optional_flags")
            .and_then(Value::as_array)
            .map(|a| collect_string_set(a))
            .unwrap_or_default();
        let mut overlap: Vec<&str> = req.intersection(&opt).copied().collect();
        overlap.sort();
        if !overlap.is_empty() {
            violations.push(format!(
                "{name}: required_flags and optional_flags share {} entrie(s): {overlap:?}",
                overlap.len()
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
            "{} required/optional flag overlap violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn collect_string_set_handles_canonical_forms() {
    use serde_json::json;
    let arr = vec![json!("--a"), json!("--b"), json!(42), json!("--a")];
    let s = collect_string_set(&arr);
    assert_eq!(s.len(), 2);
    assert!(s.contains("--a"));
    assert!(s.contains("--b"));
}
