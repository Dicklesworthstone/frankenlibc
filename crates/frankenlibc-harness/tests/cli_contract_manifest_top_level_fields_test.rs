//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare the canonical set of top-level fields (bd-p1j9d). Catches
//! manifests that drop or rename core descriptor fields.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_TOP_LEVEL_FIELDS: &[&str] = &[
    "schema_version",
    "manifest_id",
    "subcommand_name",
    "binary_target",
    "purpose",
    "summary",
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
fn every_cli_contract_manifest_declares_all_required_top_level_fields() -> TestResult {
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
        let obj = manifest
            .as_object()
            .ok_or_else(|| format!("{stem}: manifest must be a JSON object"))?;
        for field in REQUIRED_TOP_LEVEL_FIELDS {
            if !obj.contains_key(*field) {
                violations.push(format!(
                    "{stem}: missing required top-level field `{field}`"
                ));
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
            "{} CLI contract top-level field violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
