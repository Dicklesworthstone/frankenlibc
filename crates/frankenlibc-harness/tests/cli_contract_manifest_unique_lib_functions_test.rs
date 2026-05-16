//! Meta-gate: every `underlying_lib_functions` array in every
//! `*_cli_contract.v1.json` manifest has no duplicate entries
//! (bd-1r5wo). Catches accidental copy-paste duplication during
//! manifest retrofit. Order-preserving uniqueness check (each entry
//! distinct from every other).

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

#[test]
fn every_cli_contract_manifest_underlying_lib_functions_are_unique() -> TestResult {
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
        let Some(Value::Array(arr)) = manifest.get("underlying_lib_functions") else {
            continue;
        };
        let mut seen: HashSet<&str> = HashSet::new();
        let mut dupes: Vec<String> = Vec::new();
        for v in arr {
            let Some(s) = v.as_str() else { continue };
            if !seen.insert(s) {
                dupes.push(s.to_string());
            }
        }
        if !dupes.is_empty() {
            violations.push(format!(
                "{name}: underlying_lib_functions has {} duplicate entrie(s): {dupes:?}",
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
            "{} cli_contract manifest underlying_lib_functions duplicate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
