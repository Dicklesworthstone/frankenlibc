//! Meta-gate: every top-level key in every `*_cli_contract.v1.json`
//! manifest contains only lowercase ASCII letters, digits, and
//! underscores (bd-qshsq). Catches drift to CamelCase, kebab-case,
//! or whitespace-containing keys that break serde snake_case
//! deserialization assumptions and HTML/markdown report generators
//! that key off canonical snake_case identifiers.

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

fn is_canonical_key(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_manifest_top_level_key_is_canonical() -> TestResult {
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
            checked += 1;
            continue;
        };
        for key in obj.keys() {
            if !is_canonical_key(key) {
                violations.push(format!(
                    "{name}: top-level key `{key}` is not lowercase snake_case"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} manifest top-level-key canonicalization violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn canonical_key_detector_handles_canonical_forms() {
    assert!(is_canonical_key("subcommand_name"));
    assert!(is_canonical_key("purpose"));
    assert!(is_canonical_key("bead_id_42"));
    assert!(!is_canonical_key(""));
    assert!(!is_canonical_key("Purpose"));
    assert!(!is_canonical_key("sub-command"));
    assert!(!is_canonical_key("sub command"));
    assert!(!is_canonical_key("CamelCase"));
}
