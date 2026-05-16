//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest should
//! declare a top-level `kind` or `type` classifier (bd-718ld follow-up to
//! bd-497oq). The current corpus predates the classifier field, so this gate
//! freezes the legacy missing count while enforcing shape for every classifier
//! that is present.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const LEGACY_CLASSIFIER_MISSING_CEILING: usize = 68;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_classifier_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn classifier_value<'a>(
    manifest: &'a Value,
    stem: &str,
    field: &str,
    violations: &mut Vec<String>,
) -> Option<&'a str> {
    let value = manifest.get(field)?;
    match value.as_str() {
        Some(s) if is_classifier_token(s) => Some(s),
        Some(s) => {
            violations.push(format!(
                "{stem}: {field}=`{s}` must be a non-empty snake_case classifier token"
            ));
            None
        }
        None => {
            violations.push(format!("{stem}: {field} must be a string when present"));
            None
        }
    }
}

#[test]
fn every_cli_contract_manifest_declares_kind_or_type_classifier() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut shape_violations: Vec<String> = Vec::new();
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

        if manifest.get("kind").is_none() && manifest.get("type").is_none() {
            missing.push(stem.to_string());
            checked += 1;
            continue;
        }

        let kind = classifier_value(&manifest, stem, "kind", &mut shape_violations);
        let ty = classifier_value(&manifest, stem, "type", &mut shape_violations);
        if let (Some(kind), Some(ty)) = (kind, ty)
            && kind != ty
        {
            shape_violations.push(format!(
                "{stem}: kind=`{kind}` and type=`{ty}` must match when both are present"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !shape_violations.is_empty() {
        return Err(format!(
            "{} CLI contract classifier shape violation(s):\n  {}",
            shape_violations.len(),
            shape_violations.join("\n  ")
        ));
    }

    if missing.len() > LEGACY_CLASSIFIER_MISSING_CEILING {
        return Err(format!(
            "{} CLI contract manifest(s) missing kind/type classifier (ceiling {LEGACY_CLASSIFIER_MISSING_CEILING}):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn classifier_token_validator_accepts_snake_case_and_rejects_noise() {
    assert!(is_classifier_token("runtime_math_contract"));
    assert!(is_classifier_token("cli_contract_v1"));
    assert!(!is_classifier_token(""));
    assert!(!is_classifier_token("CLIContract"));
    assert!(!is_classifier_token("cli-contract"));
    assert!(!is_classifier_token("cli contract"));
}
