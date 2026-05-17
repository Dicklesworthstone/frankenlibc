//! Meta-gate: when a `*_cli_contract.v1.json` manifest's `summary`
//! field is an object, it has at least 1 field (bd-lx6x2). Catches
//! stub manifests that ship `summary: {}` placeholders. The
//! companion bd-wvkcd already enforces `summary` is non-null /
//! non-empty more broadly; this gate adds a typed object-shape check.

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
fn every_cli_contract_summary_object_has_at_least_one_field() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_objects = 0usize;
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
        let Some(Value::Object(o)) = manifest.get("summary") else {
            continue;
        };
        checked_objects += 1;
        if o.is_empty() {
            violations.push(format!("{name}: summary object is empty"));
        }
    }

    assert!(
        checked_objects >= 30,
        "expected at least 30 cli_contract summary objects; found {checked_objects}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} summary-object-empty violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
