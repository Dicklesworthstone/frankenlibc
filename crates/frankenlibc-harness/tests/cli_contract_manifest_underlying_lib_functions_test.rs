//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares `underlying_lib_functions` as a
//! non-empty array of non-empty strings (bd-mlnfd). Catches manifests
//! that drop the lib-function provenance link, which is the canonical
//! way to trace a CLI subcommand back to the host libc surface it
//! exercises.

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
fn every_cli_contract_manifest_underlying_lib_functions_is_non_empty_array() -> TestResult {
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
        match manifest.get("underlying_lib_functions") {
            Some(Value::Array(arr)) if arr.is_empty() => {
                violations.push(format!("{name}: `underlying_lib_functions` is empty array"));
            }
            Some(Value::Array(arr)) => {
                for (i, v) in arr.iter().enumerate() {
                    match v.as_str() {
                        Some(s) if !s.is_empty() => {}
                        Some(_) => violations.push(format!(
                            "{name}: underlying_lib_functions[{i}] is empty string"
                        )),
                        None => violations.push(format!(
                            "{name}: underlying_lib_functions[{i}] is not a string"
                        )),
                    }
                }
            }
            Some(_) => {
                violations.push(format!(
                    "{name}: `underlying_lib_functions` is not an array"
                ));
            }
            None => {
                violations.push(format!(
                    "{name}: missing required field `underlying_lib_functions`"
                ));
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
            "{} cli_contract manifest underlying_lib_functions violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
