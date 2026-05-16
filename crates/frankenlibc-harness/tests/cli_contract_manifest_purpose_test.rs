//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `purpose` string of meaningful length (bd-fmaz4).
//!
//! Fifth in the bd-intan/bd-0uox4/bd-fwryt/bd-3flf0 meta-gate cluster.
//! Catches stub or placeholder manifests committed without a real narrative
//! describing what the subcommand pins and why.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_PURPOSE_CHARS: usize = 80;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_declares_substantive_purpose() -> TestResult {
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
        let purpose = manifest
            .get("purpose")
            .and_then(Value::as_str)
            .unwrap_or("");
        if purpose.trim().len() < MIN_PURPOSE_CHARS {
            violations.push(format!(
                "{stem}: purpose length {} below minimum {MIN_PURPOSE_CHARS}",
                purpose.trim().len()
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
            "{} CLI contract manifest purpose violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
