//! Meta-gate: every `*_cli_contract.v1.json` manifest's `purpose`
//! field is at most 1000 characters (bd-tpx5l). Catches free-form
//! documentation accidentally written into the purpose field
//! instead of a doc-link, external evidence file, or proper notes
//! field. The `purpose` field renders as a one-paragraph summary
//! in downstream HTML/markdown reports; longer prose belongs
//! elsewhere.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MAX_LEN: usize = 1000;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_purpose_within_max_length() -> TestResult {
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
        let Some(purpose) = manifest.get("purpose").and_then(Value::as_str) else {
            checked += 1;
            continue;
        };
        let len = purpose.chars().count();
        if len > MAX_LEN {
            violations.push(format!(
                "{name}: purpose is {len} chars (must be <= {MAX_LEN})"
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
            "{} manifest purpose max-length violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
