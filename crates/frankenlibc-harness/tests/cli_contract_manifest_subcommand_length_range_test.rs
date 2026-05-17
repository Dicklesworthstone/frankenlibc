//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `subcommand_name` length is in the inclusive range 3..=60
//! characters (bd-2ddnb). Names shorter than 3 chars are too
//! cryptic to be self-documenting subcommands; names longer than
//! 60 chars indicate the field is being misused as a sentence or
//! description (subcommand_name is a clap subcommand identifier,
//! not free-form documentation).

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_LEN: usize = 3;
const MAX_LEN: usize = 60;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_subcommand_name_within_length_range() -> TestResult {
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
        let Some(s) = manifest.get("subcommand_name").and_then(Value::as_str) else {
            checked += 1;
            continue;
        };
        let len = s.chars().count();
        if !(MIN_LEN..=MAX_LEN).contains(&len) {
            violations.push(format!(
                "{name}: subcommand_name `{s}` length {len} outside {MIN_LEN}..={MAX_LEN}"
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
            "{} subcommand_name length-range violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
