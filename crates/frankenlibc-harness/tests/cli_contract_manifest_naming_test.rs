//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` filename must
//! match its embedded `subcommand_name` field, with the standard
//! kebab-with-underscores convention (bd-0uox4).
//!
//! Catches naming-mismatch regressions like the one fixed under bd-vr2q2:
//! `recommend_healing_cli_contract.v1.json` did not match its
//! `recommend-healing-for-canonical-class` subcommand name.

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
fn every_cli_contract_manifest_filename_matches_embedded_subcommand_name() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut mismatches: Vec<String> = Vec::new();
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
        let prefix = stem
            .strip_suffix("_cli_contract.v1.json")
            .expect("checked suffix");
        let expected_kebab = prefix.replace('_', "-");

        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))?;
        let actual = manifest
            .get("subcommand_name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{path:?} missing subcommand_name field"))?;
        if actual != expected_kebab {
            mismatches.push(format!(
                "{stem}: filename implies subcommand `{expected_kebab}` but manifest says `{actual}`"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !mismatches.is_empty() {
        return Err(format!(
            "{} CLI contract manifest filename/subcommand mismatch(es):\n  {}",
            mismatches.len(),
            mismatches.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn every_cli_contract_manifest_declares_binary_target_harness() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
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
        let actual = manifest
            .get("binary_target")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        if actual != "harness" {
            violations.push(format!(
                "{stem}: binary_target=`{actual}` (expected `harness`)"
            ));
        }
    }

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest binary_target violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
