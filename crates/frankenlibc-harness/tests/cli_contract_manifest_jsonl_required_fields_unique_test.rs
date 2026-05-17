//! Meta-gate: every `jsonl_output_contract.required_fields` array
//! across all `*_cli_contract.v1.json` manifests has no duplicate
//! entries (bd-ooxu5). Catches accidental copy-paste duplication
//! during manifest authoring. Order is intentionally NOT enforced —
//! field order in this section often follows logical grouping
//! (record-kind first, then identifiers, then payload) rather than
//! alphabetic order.

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
fn every_cli_contract_jsonl_required_fields_array_has_no_duplicates() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_manifests = 0usize;
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
        let Some(Value::Array(arr)) = manifest
            .get("jsonl_output_contract")
            .and_then(|j| j.get("required_fields"))
        else {
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
                "{name}: jsonl_output_contract.required_fields has {} duplicate entrie(s): {dupes:?}",
                dupes.len()
            ));
        }
        checked_manifests += 1;
    }

    assert!(
        checked_manifests >= 20,
        "expected at least 20 jsonl_output_contract manifests with required_fields; found {checked_manifests}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl required_fields duplicate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
