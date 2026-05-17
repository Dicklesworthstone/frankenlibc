//! Meta-gate: no `*_cli_contract.v1.json` manifest declares a `bead`
//! field set to a known placeholder string like `bd-XXXXXX`,
//! `bd-TODO`, `bd-placeholder`, `TODO`, or `TBD` (bd-z9ske). Catches
//! manifests that were generated from a template without filling in
//! the real bead id.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const PLACEHOLDER_BEAD_IDS: &[&str] = &[
    "bd-XXXXXX",
    "bd-xxxxxx",
    "bd-TODO",
    "bd-todo",
    "bd-placeholder",
    "bd-PLACEHOLDER",
    "TODO",
    "TBD",
    "todo",
    "tbd",
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
fn no_cli_contract_manifest_has_placeholder_bead_id() -> TestResult {
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
        if let Some(bead) = manifest.get("bead").and_then(Value::as_str) {
            if PLACEHOLDER_BEAD_IDS.contains(&bead) {
                violations.push(format!("{name}: bead `{bead}` is a placeholder"));
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
            "{} placeholder-bead violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
