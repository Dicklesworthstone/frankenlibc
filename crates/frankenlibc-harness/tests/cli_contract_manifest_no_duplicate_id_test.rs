//! Meta-gate: no two `tests/conformance/*_cli_contract.v1.json` files may
//! share the same `manifest_id` field (bd-92216). manifest_id must uniquely
//! identify the contract. Catches copy-paste manifest duplication.
//!
//! Also asserts no two manifests share the same `subcommand_name` — each
//! harness subcommand should have exactly one CLI contract manifest.

use std::collections::BTreeMap;
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

fn collect_field(conformance_dir: &Path, field: &str) -> TestResult<BTreeMap<String, Vec<String>>> {
    let mut by_value: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let entries = std::fs::read_dir(conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;
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
        if let Some(value) = manifest.get(field).and_then(Value::as_str) {
            by_value
                .entry(value.to_string())
                .or_default()
                .push(stem.to_string());
        }
    }
    Ok(by_value)
}

#[test]
fn manifest_id_is_unique_across_cli_contract_manifests() -> TestResult {
    let root = workspace_root()?;
    let dir = root.join("tests").join("conformance");
    let by_id = collect_field(&dir, "manifest_id")?;
    let duplicates: Vec<String> = by_id
        .iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(id, files)| format!("manifest_id=`{id}` is shared by: {files:?}"))
        .collect();
    if !duplicates.is_empty() {
        return Err(format!(
            "{} manifest_id collision(s):\n  {}",
            duplicates.len(),
            duplicates.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn subcommand_name_is_unique_across_cli_contract_manifests() -> TestResult {
    let root = workspace_root()?;
    let dir = root.join("tests").join("conformance");
    let by_subcommand = collect_field(&dir, "subcommand_name")?;
    let duplicates: Vec<String> = by_subcommand
        .iter()
        .filter(|(_, files)| files.len() > 1)
        .map(|(sub, files)| format!("subcommand_name=`{sub}` pinned by: {files:?}"))
        .collect();
    if !duplicates.is_empty() {
        return Err(format!(
            "{} subcommand_name collision(s):\n  {}",
            duplicates.len(),
            duplicates.join("\n  ")
        ));
    }
    Ok(())
}
