//! Meta-gate: every entry in `required_flags` of every
//! `*_cli_contract.v1.json` manifest starts with `--` (long-form CLI
//! flag) (bd-avzpt). Short single-dash flags are conventionally used
//! for optional convenience, so required flags should always be the
//! explicit long form for clarity in CI / scripted invocations.

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
fn every_cli_contract_required_flag_entry_uses_long_form() -> TestResult {
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
            if !s.starts_with("--") {
                violations.push(format!(
                    "{name}: required_flags[{i}] = `{s}` does not start with `--` (required flags must be long-form)"
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
            "{} required_flags long-form violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
