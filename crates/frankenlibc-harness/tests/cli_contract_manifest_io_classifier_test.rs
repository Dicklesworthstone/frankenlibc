//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares at least one I/O classifier field:
//! `io_pattern`, `output_contract`, or `jsonl_output_contract`
//! (bd-jrx0f). Catches manifests that drop the I/O classifier entirely
//! during retrofit.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const IO_CLASSIFIER_FIELDS: &[&str] = &["io_pattern", "output_contract", "jsonl_output_contract"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_declares_io_classifier() -> TestResult {
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
        let has_any_classifier = IO_CLASSIFIER_FIELDS
            .iter()
            .any(|field| manifest.get(*field).is_some());
        if !has_any_classifier {
            violations.push(format!(
                "{name}: missing all I/O classifier fields (need one of {IO_CLASSIFIER_FIELDS:?})"
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
            "{} cli_contract manifest io-classifier violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }

    Ok(())
}
