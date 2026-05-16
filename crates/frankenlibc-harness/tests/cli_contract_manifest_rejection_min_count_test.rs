//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest's
//! `rejected_evidence_kinds` array must declare at least 3 entries (bd-0fl3y).
//! A contract that only rejects 1-2 things is too thin to meaningfully
//! fail-close. Current measured min across the corpus is 3.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_REJECTED_EVIDENCE_KINDS: usize = 3;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_rejection_list_has_minimum_three_entries() -> TestResult {
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
        if arr.len() < MIN_REJECTED_EVIDENCE_KINDS {
            violations.push(format!(
                "{stem}: rejected_evidence_kinds has {} entries (minimum {MIN_REJECTED_EVIDENCE_KINDS})",
                arr.len()
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest rejection count violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
