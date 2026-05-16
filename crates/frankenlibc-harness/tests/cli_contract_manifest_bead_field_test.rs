//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `bead` field matching the canonical `bd-<slug>` pattern.
//! Catches manifests committed without an anchoring bead.

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

fn is_valid_bead_id(value: &str) -> bool {
    if !value.starts_with("bd-") {
        return false;
    }
    let slug = &value[3..];
    if slug.is_empty() {
        return false;
    }
    slug.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

#[test]
fn every_cli_contract_manifest_declares_canonical_bead_id() -> TestResult {
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
        let bead = manifest
            .get("bead")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        if !is_valid_bead_id(bead) {
            violations.push(format!(
                "{stem}: bead=`{bead}` does not match canonical `bd-<slug>` pattern"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest bead-id violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn bead_id_validator_accepts_canonical_forms_and_rejects_garbage() {
    assert!(is_valid_bead_id("bd-intan"));
    assert!(is_valid_bead_id("bd-bp8fl.10.3"));
    assert!(is_valid_bead_id("bd-9ws64"));
    assert!(!is_valid_bead_id(""));
    assert!(!is_valid_bead_id("bd-"));
    assert!(!is_valid_bead_id("intan"));
    assert!(!is_valid_bead_id("BD-INTAN"));
    assert!(!is_valid_bead_id("bd-has space"));
}
