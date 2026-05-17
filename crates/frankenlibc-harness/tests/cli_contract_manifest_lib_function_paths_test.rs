//! Meta-gate: every entry in `underlying_lib_functions` of every
//! `*_cli_contract.v1.json` manifest, and every singular
//! `underlying_lib_function` value when present, contains at least one
//! `::` separator — i.e. it's a Rust-style path like
//! `frankenlibc_harness::module::function` (bd-wmjs7). Catches stub
//! entries like `TODO`, `WIP`, bare crate names without a `::` path,
//! or filename-style entries that won't resolve as real lib paths.
//! The singular alias check pins bd-pcvbm.

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

fn looks_like_rust_path(s: &str) -> bool {
    s.contains("::") && !s.starts_with("::") && !s.ends_with("::") && !s.contains(' ')
}

#[test]
fn every_cli_contract_manifest_underlying_lib_function_entries_look_like_rust_paths() -> TestResult
{
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked_manifests = 0usize;
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
            checked_entries += 1;
            match v.as_str() {
                None => violations.push(format!(
                    "{name}: underlying_lib_functions[{i}] is not a string"
                )),
                Some(s) if !looks_like_rust_path(s) => violations.push(format!(
                    "{name}: underlying_lib_functions[{i}] = `{s}` is not a Rust path (missing `::`, leading/trailing `::`, or contains whitespace)"
                )),
                Some(_) => {}
            }
        }
        checked_manifests += 1;
    }

    assert!(
        checked_manifests >= 30,
        "expected at least 30 cli_contract manifests; found {checked_manifests}"
    );
    assert!(
        checked_entries >= 60,
        "expected at least 60 underlying_lib_functions entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} underlying_lib_function path violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn every_cli_contract_manifest_singular_underlying_lib_function_looks_like_rust_path() -> TestResult
{
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
        let Some(value) = manifest.get("underlying_lib_function") else {
            continue;
        };
        checked_entries += 1;
        match value.as_str() {
            None => violations.push(format!("{name}: underlying_lib_function is not a string")),
            Some(s) if !looks_like_rust_path(s) => violations.push(format!(
                "{name}: underlying_lib_function = `{s}` is not a Rust path (missing `::`, leading/trailing `::`, or contains whitespace)"
            )),
            Some(_) => {}
        }
    }

    assert!(
        checked_entries >= 20,
        "expected at least 20 singular underlying_lib_function entries; found {checked_entries}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} singular underlying_lib_function path violation(s) across {checked_entries} entries:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn rust_path_validator_handles_canonical_forms() {
    assert!(looks_like_rust_path("foo::bar"));
    assert!(looks_like_rust_path(
        "frankenlibc_harness::module::function"
    ));
    assert!(looks_like_rust_path("a::b::c::d"));
    assert!(!looks_like_rust_path(""));
    assert!(!looks_like_rust_path("foo"));
    assert!(!looks_like_rust_path("::foo"));
    assert!(!looks_like_rust_path("foo::"));
    assert!(!looks_like_rust_path("foo bar::baz"));
    assert!(!looks_like_rust_path("TODO"));
}
