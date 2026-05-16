//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares the
//! singular `underlying_lib_function` field, its value must equal
//! `underlying_lib_functions[0]` (bd-25ide). The singular form is a
//! legacy redundant field; when present it must stay in sync with the
//! authoritative plural form's first entry. Manifests without the
//! singular form are skipped.

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

#[test]
fn cli_contract_manifest_singular_matches_first_plural_entry() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_manifests = 0usize;
    let mut checked_with_singular = 0usize;
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
        checked_manifests += 1;
        let Some(singular) = manifest
            .get("underlying_lib_function")
            .and_then(Value::as_str)
        else {
            continue;
        };
        checked_with_singular += 1;
        let first = manifest
            .get("underlying_lib_functions")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str);
        match first {
            None => violations.push(format!(
                "{name}: has singular `underlying_lib_function`=`{singular}` but `underlying_lib_functions[0]` is missing"
            )),
            Some(f) if f != singular => violations.push(format!(
                "{name}: singular `{singular}` != plural[0] `{f}`"
            )),
            Some(_) => {}
        }
    }

    assert!(
        checked_manifests >= 30,
        "expected at least 30 cli_contract manifests; found {checked_manifests}"
    );
    assert!(
        checked_with_singular >= 5,
        "expected at least 5 manifests with singular underlying_lib_function; found {checked_with_singular}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} singular/plural[0] divergence(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
