//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `rejected_evidence_kinds` JSON array of snake_case
//! strings. Catches manifests that don't enumerate the fail-closed evidence
//! kinds the gate test should reject.

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
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_manifest_declares_nonempty_rejected_evidence_kinds() -> TestResult {
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
        match manifest.get("rejected_evidence_kinds") {
            None => violations.push(format!("{stem}: rejected_evidence_kinds missing")),
            Some(Value::Array(a)) if a.is_empty() => {
                violations.push(format!("{stem}: rejected_evidence_kinds must be non-empty"))
            }
            Some(Value::Array(a)) => {
                let bad: Vec<String> = a
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|s| !is_snake_case(s))
                    .map(String::from)
                    .collect();
                if !bad.is_empty() {
                    violations.push(format!(
                        "{stem}: rejected_evidence_kinds has non-snake_case entries: {bad:?}"
                    ));
                }
            }
            Some(_) => violations.push(format!(
                "{stem}: rejected_evidence_kinds must be a JSON array"
            )),
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest rejected_evidence_kinds violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_validator_accepts_canonical_forms_and_rejects_garbage() {
    assert!(is_snake_case("missing_required_flag"));
    assert!(is_snake_case("unknown_mode_accepted"));
    assert!(is_snake_case("policy_hash_drift_v1"));
    assert!(!is_snake_case(""));
    assert!(!is_snake_case("HasUpper"));
    assert!(!is_snake_case("has-dash"));
    assert!(!is_snake_case("has space"));
}
