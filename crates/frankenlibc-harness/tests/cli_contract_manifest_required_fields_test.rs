//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares the five canonical structural
//! classifier fields: `purpose`, `subcommand_name`, `binary_target`,
//! `schema_version`, and `source_commit` (bd-497oq). Each must be a
//! non-empty string. Catches incomplete manifests that drop the
//! classifier set during retrofit.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_STRING_FIELDS: &[&str] = &[
    "purpose",
    "subcommand_name",
    "binary_target",
    "schema_version",
    "source_commit",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_declares_required_classifier_fields() -> TestResult {
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
        for field in REQUIRED_STRING_FIELDS {
            match manifest.get(*field).and_then(Value::as_str) {
                Some(v) if !v.is_empty() => {}
                Some(_) => violations.push(format!("{name}: `{field}` is empty string")),
                None => violations.push(format!("{name}: missing required field `{field}`")),
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
            "{} cli_contract manifest required-field violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
