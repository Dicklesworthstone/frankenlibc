//! Meta-gate: every entry in every `required_flags` array across
//! all `*_cli_contract.v1.json` manifests contains no `=` character
//! (bd-fxzng). Flags should be bare names like `--output`; values
//! come in separate argv positions. Catches `--foo=bar` form that
//! breaks clap's structured parser. Sibling to bd-3xozg's
//! optional_flags rule.

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

fn is_flag_only_form(s: &str) -> bool {
    !s.contains('=')
}

#[test]
fn every_cli_contract_required_flags_are_flag_only_form() -> TestResult {
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
        let Some(Value::Array(arr)) = manifest.get("required_flags") else {
            continue;
        };
        for (i, v) in arr.iter().enumerate() {
            let Some(s) = v.as_str() else {
                continue;
            };
            checked_entries += 1;
            if !is_flag_only_form(s) {
                violations.push(format!(
                    "{name}: required_flags[{i}] = `{s}` contains `=`; use flag-only form"
                ));
            }
        }
    }

    assert!(
        checked_entries >= 30,
        "expected at least 30 required_flags entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} required_flags flag-only-form violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn flag_only_form_detector_handles_canonical_forms() {
    assert!(is_flag_only_form("--output"));
    assert!(is_flag_only_form("-o"));
    assert!(is_flag_only_form("--foo-bar"));
    assert!(!is_flag_only_form("--output=foo"));
    assert!(!is_flag_only_form("--key=value"));
    assert!(!is_flag_only_form("="));
}
