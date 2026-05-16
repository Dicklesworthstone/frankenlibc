//! Meta-gate: when a `tests/conformance/*_cli_contract.v1.json` manifest
//! declares `mode_enum`, it must be a non-empty JSON array of distinct
//! lowercase ASCII strings (bd-sc4nx). Catches schema drift for the
//! mode-enum family.

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

fn is_lower_ascii(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

#[test]
fn mode_enum_when_present_is_nonempty_distinct_lowercase_array() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut declared = 0usize;
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
        let Some(mode_enum) = manifest.get("mode_enum") else {
            continue;
        };
        let Some(arr) = mode_enum.as_array() else {
            violations.push(format!("{stem}: mode_enum must be a JSON array"));
            continue;
        };
        if arr.is_empty() {
            violations.push(format!("{stem}: mode_enum must be non-empty"));
            continue;
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for (i, entry) in arr.iter().enumerate() {
            let Some(s) = entry.as_str() else {
                violations.push(format!(
                    "{stem}: mode_enum[{i}] must be a string (got {entry:?})"
                ));
                continue;
            };
            if !is_lower_ascii(s) {
                violations.push(format!(
                    "{stem}: mode_enum[{i}]=`{s}` is not lowercase ASCII"
                ));
            }
            if !seen.insert(s) {
                violations.push(format!("{stem}: mode_enum[{i}]=`{s}` is a duplicate"));
            }
        }
        declared += 1;
    }

    assert!(
        declared >= 3,
        "expected at least 3 manifests with mode_enum; found {declared}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} mode_enum shape violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
