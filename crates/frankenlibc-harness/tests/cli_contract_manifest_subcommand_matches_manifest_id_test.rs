//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `subcommand_name` equals `manifest_id` with the trailing
//! `-cli-contract` suffix stripped off (bd-2701v). Catches drift
//! between the manifest id and the subcommand name it pins.

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
fn every_cli_contract_subcommand_name_matches_manifest_id_root() -> TestResult {
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
        let manifest_id = manifest
            .get("manifest_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let subcmd = manifest
            .get("subcommand_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let expected = manifest_id
            .strip_suffix("-cli-contract")
            .unwrap_or(manifest_id);
        if subcmd != expected {
            violations.push(format!(
                "{name}: subcommand_name `{subcmd}` != manifest_id stripped of `-cli-contract` (`{expected}`)"
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
            "{} subcommand_name vs manifest_id drift violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
