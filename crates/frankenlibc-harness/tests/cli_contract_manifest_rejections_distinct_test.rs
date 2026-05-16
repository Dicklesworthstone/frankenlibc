//! Meta-gate: no two entries in the `rejected_evidence_kinds` array of any
//! `tests/conformance/*_cli_contract.v1.json` may be equal (bd-zxryv).
//! Catches accidental duplication that inflates rejection counts without
//! adding coverage. Sister to bd-t1ykj for underlying_lib_functions.

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
fn rejected_evidence_kinds_entries_are_distinct_within_each_manifest() -> TestResult {
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
        let Some(arr) = manifest
            .get("rejected_evidence_kinds")
            .and_then(Value::as_array)
        else {
            continue;
        };
        let mut seen: HashSet<&str> = HashSet::new();
        for entry in arr {
            let Some(s) = entry.as_str() else {
                continue;
            };
            if !seen.insert(s) {
                violations.push(format!(
                    "{stem}: rejected_evidence_kinds contains duplicate `{s}`"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 manifests with rejected_evidence_kinds; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} rejected_evidence_kinds duplication violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
