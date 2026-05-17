//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares
//! `jsonl_output_contract.required_fields`, the array has at least 2
//! entries (bd-68t8t) — a record-kind discriminator + at least one
//! payload field. Catches manifests with single-field stubs. The
//! corpus currently has all 28 such arrays at >=2 entries.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_REQUIRED_FIELDS: usize = 2;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_jsonl_required_fields_has_min_entries() -> TestResult {
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
        let Some(Value::Array(arr)) = manifest
            .get("jsonl_output_contract")
            .and_then(|j| j.get("required_fields"))
        else {
            continue;
        };
        let len = arr.len();
        if len < MIN_REQUIRED_FIELDS {
            violations.push(format!(
                "{name}: jsonl_output_contract.required_fields has {len} entrie(s) (minimum {MIN_REQUIRED_FIELDS})"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 jsonl required_fields arrays; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} jsonl required_fields min-count violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
