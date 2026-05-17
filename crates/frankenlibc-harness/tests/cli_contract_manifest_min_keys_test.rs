//! Meta-gate: every `*_cli_contract.v1.json` manifest has at least
//! three top-level object keys (bd-ca7su). Rules out skeletal/stub
//! manifests with only one or two fields — a real CLI contract
//! manifest carries at minimum a subcommand identifier, a stated
//! purpose, and at least one shape-of-behavior field (exit codes,
//! flags, expected output schema, source pins, etc.). Below three
//! keys, the manifest is not load-bearing evidence.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_KEYS: usize = 3;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_has_minimum_top_level_keys() -> TestResult {
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
        let Some(obj) = manifest.as_object() else {
            violations.push(format!("{name}: top-level value is not a JSON object"));
            checked += 1;
            continue;
        };
        if obj.len() < MIN_KEYS {
            violations.push(format!(
                "{name}: only {} top-level key(s) (require >= {MIN_KEYS})",
                obj.len()
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
            "{} top-level-keys minimum violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
