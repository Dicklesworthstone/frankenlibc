//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares an
//! `io_pattern`, the string is trimmed (no leading/trailing
//! whitespace) (bd-l1am5). Catches sloppy edits that paste io_pattern
//! values with stray surrounding whitespace.

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
fn every_cli_contract_io_pattern_is_trimmed() -> TestResult {
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
        let Some(s) = manifest.get("io_pattern").and_then(Value::as_str) else {
            continue;
        };
        if s != s.trim() {
            violations.push(format!(
                "{name}: io_pattern `{s}` has leading/trailing whitespace"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 io_pattern-bearing manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} io_pattern-trimmed violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
