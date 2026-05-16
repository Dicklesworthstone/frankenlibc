//! Meta-gate: no flag entry may appear twice within `required_flags`, twice
//! within `optional_flags`, or once each in both arrays of any
//! `tests/conformance/*_cli_contract.v1.json` manifest (bd-k5s1f). Catches
//! duplicate-flag schema drift that would make a flag appear in both
//! categories simultaneously.

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

fn collect_flags<'a>(manifest: &'a Value, field: &str) -> Vec<&'a str> {
    manifest
        .get(field)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

#[test]
fn flags_arrays_have_distinct_entries_within_and_across_required_optional() -> TestResult {
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

        let required = collect_flags(&manifest, "required_flags");
        let optional = collect_flags(&manifest, "optional_flags");

        let mut req_seen: HashSet<&str> = HashSet::new();
        for f in &required {
            if !req_seen.insert(f) {
                violations.push(format!("{stem}: required_flags contains duplicate `{f}`"));
            }
        }
        let mut opt_seen: HashSet<&str> = HashSet::new();
        for f in &optional {
            if !opt_seen.insert(f) {
                violations.push(format!("{stem}: optional_flags contains duplicate `{f}`"));
            }
        }
        for f in &optional {
            if req_seen.contains(*f) {
                violations.push(format!(
                    "{stem}: flag `{f}` appears in both required_flags and optional_flags"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} flag-array distinctness violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
