//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares a non-empty `summary` (bd-wvkcd).
//! Catches manifests that drop the summary classifier. Accepts:
//! - `summary` as a string with at least `MIN_SUMMARY_STRING_LENGTH` chars
//! - `summary` as a non-empty object (the canonical form across the
//!   current corpus, where each subcommand records a structured
//!   bead/subcommand/claim_status block)
//! - `summary` as a non-empty array

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_SUMMARY_STRING_LENGTH: usize = 30;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_has_non_empty_summary() -> TestResult {
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
        match manifest.get("summary") {
            None => violations.push(format!("{name}: missing required field `summary`")),
            Some(Value::Null) => violations.push(format!("{name}: `summary` is null")),
            Some(Value::String(s)) if s.len() < MIN_SUMMARY_STRING_LENGTH => {
                violations.push(format!(
                    "{name}: summary string is {} chars (minimum {MIN_SUMMARY_STRING_LENGTH})",
                    s.len()
                ))
            }
            Some(Value::Object(o)) if o.is_empty() => {
                violations.push(format!("{name}: `summary` is empty object"))
            }
            Some(Value::Array(a)) if a.is_empty() => {
                violations.push(format!("{name}: `summary` is empty array"))
            }
            Some(_) => {}
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest summary violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
