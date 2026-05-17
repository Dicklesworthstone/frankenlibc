//! Meta-gate: every entry in `underlying_lib_functions` of every
//! `*_cli_contract.v1.json` manifest starts with a recognized
//! frankenlibc workspace crate prefix (bd-7fq4t). The closed set
//! tracks the actual crates that paired CLI contracts wire into:
//! `frankenlibc_harness`, `frankenlibc_membrane`,
//! `frankenlibc_fixture_exec`, and the bare `harness` legacy alias.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const KNOWN_CRATE_PREFIXES: &[&str] = &[
    "frankenlibc_harness::",
    "frankenlibc_membrane::",
    "frankenlibc_fixture_exec::",
    "harness::",
];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn starts_with_known_crate_prefix(s: &str) -> bool {
    KNOWN_CRATE_PREFIXES.iter().any(|p| s.starts_with(p))
}

#[test]
fn every_cli_contract_underlying_lib_function_starts_with_known_crate() -> TestResult {
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
        let Some(Value::Array(arr)) = manifest.get("underlying_lib_functions") else {
            continue;
        };
        for (i, v) in arr.iter().enumerate() {
            let Some(s) = v.as_str() else {
                continue;
            };
            checked_entries += 1;
            if !starts_with_known_crate_prefix(s) {
                violations.push(format!(
                    "{name}: underlying_lib_functions[{i}] = `{s}` does not start with a known crate prefix ({KNOWN_CRATE_PREFIXES:?})"
                ));
            }
        }
    }

    assert!(
        checked_entries >= 60,
        "expected at least 60 underlying_lib_functions entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} crate-prefix violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn crate_prefix_validator_handles_canonical_forms() {
    assert!(starts_with_known_crate_prefix("frankenlibc_harness::a::b"));
    assert!(starts_with_known_crate_prefix("frankenlibc_membrane::foo"));
    assert!(starts_with_known_crate_prefix(
        "frankenlibc_fixture_exec::a"
    ));
    assert!(starts_with_known_crate_prefix("harness::a"));
    assert!(!starts_with_known_crate_prefix(""));
    assert!(!starts_with_known_crate_prefix("foo::bar"));
    assert!(!starts_with_known_crate_prefix("frankenlibc_harness"));
    assert!(!starts_with_known_crate_prefix("FRANKENLIBC_HARNESS::a"));
}
