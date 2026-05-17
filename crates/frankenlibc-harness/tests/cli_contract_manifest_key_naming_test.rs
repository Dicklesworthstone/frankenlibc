//! Meta-gate: every top-level key in `tests/conformance/*_cli_contract.v1.json`
//! must conform to snake_case (bd-t0kyy), and every policy key must do the
//! same (bd-lzd7c). Catches camelCase, kebab-case, or typo-introduced keys that
//! would silently bypass other gates.

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

fn is_snake_case(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_manifest_top_level_key_is_snake_case() -> TestResult {
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
        let Some(obj) = manifest.as_object() else {
            continue;
        };
        for key in obj.keys() {
            if !is_snake_case(key) {
                violations.push(format!("{stem}: top-level key `{key}` is not snake_case"));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract top-level key naming violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn every_cli_contract_manifest_policy_key_is_snake_case() -> TestResult {
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
        let Some(policy) = manifest.get("policy") else {
            violations.push(format!("{stem}: missing policy object"));
            continue;
        };
        let Some(policy) = policy.as_object() else {
            violations.push(format!("{stem}: policy must be an object"));
            continue;
        };
        for key in policy.keys() {
            if !is_snake_case(key) {
                violations.push(format!("{stem}: policy key `{key}` is not snake_case"));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifest policy objects; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract policy key naming violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_validator_accepts_canonical_forms_and_rejects_garbage() {
    assert!(is_snake_case("manifest_id"));
    assert!(is_snake_case("schema_version"));
    assert!(is_snake_case("default_log_path"));
    assert!(!is_snake_case(""));
    assert!(!is_snake_case("1manifest_id"));
    assert!(!is_snake_case("_manifest_id"));
    assert!(!is_snake_case("manifestId"));
    assert!(!is_snake_case("manifest-id"));
    assert!(!is_snake_case("Manifest_Id"));
}
