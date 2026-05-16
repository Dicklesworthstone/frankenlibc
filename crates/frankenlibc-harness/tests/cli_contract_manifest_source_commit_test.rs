//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `source_commit` string (bd-0m86d). Catches manifests
//! committed without git provenance. Uses a ratchet for the pre-existing
//! legacy violations.

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
fn every_cli_contract_manifest_declares_non_empty_source_commit() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut bad_shape: Vec<String> = Vec::new();
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
        match manifest.get("source_commit") {
            None => missing.push(stem.to_string()),
            Some(Value::String(s)) if s.is_empty() => missing.push(stem.to_string()),
            Some(Value::String(s)) if s.len() < 7 => bad_shape.push(format!(
                "{stem}: source_commit=`{s}` is shorter than a 7-char git hex prefix"
            )),
            Some(Value::String(_)) => {}
            Some(other) => bad_shape.push(format!(
                "{stem}: source_commit must be a JSON string (got {other:?})"
            )),
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !bad_shape.is_empty() {
        return Err(format!(
            "{} CLI contract manifest source_commit shape violation(s):\n  {}",
            bad_shape.len(),
            bad_shape.join("\n  ")
        ));
    }

    const LEGACY_SOURCE_COMMIT_MISSING_CEILING: usize = 0;
    if missing.len() > LEGACY_SOURCE_COMMIT_MISSING_CEILING {
        return Err(format!(
            "{} CLI contract manifest(s) with missing source_commit (ceiling {LEGACY_SOURCE_COMMIT_MISSING_CEILING}):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}
