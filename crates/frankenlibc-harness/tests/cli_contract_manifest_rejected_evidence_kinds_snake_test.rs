//! Meta-gate: every entry in every `rejected_evidence_kinds` array
//! across all `*_cli_contract.v1.json` manifests is a lowercase
//! snake_case identifier (bd-th92v). Catches PascalCase / camelCase /
//! kebab-case drift in rejection-kind tags, plus stub values like
//! `TODO` or empty strings.

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

fn is_snake_case_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_rejected_evidence_kinds_entry_is_snake_case() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_entries = 0usize;
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
        let Some(Value::Array(arr)) = manifest.get("rejected_evidence_kinds") else {
            continue;
        };
        for (i, v) in arr.iter().enumerate() {
            checked_entries += 1;
            match v.as_str() {
                Some(s) if is_snake_case_identifier(s) => {}
                Some(other) => violations.push(format!(
                    "{name}: rejected_evidence_kinds[{i}] = `{other}` is not snake_case"
                )),
                None => violations.push(format!(
                    "{name}: rejected_evidence_kinds[{i}] is not a string"
                )),
            }
        }
    }

    assert!(
        checked_entries >= 100,
        "expected at least 100 rejected_evidence_kinds entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} rejected_evidence_kinds snake_case violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_identifier_validator_handles_canonical_forms() {
    assert!(is_snake_case_identifier("missing_output_flag"));
    assert!(is_snake_case_identifier("kind_mismatch"));
    assert!(is_snake_case_identifier("ok"));
    assert!(!is_snake_case_identifier(""));
    assert!(!is_snake_case_identifier("Missing_Output_Flag"));
    assert!(!is_snake_case_identifier("missingOutputFlag"));
    assert!(!is_snake_case_identifier("missing-output-flag"));
    assert!(!is_snake_case_identifier("_missing"));
    assert!(!is_snake_case_identifier("9missing"));
}
