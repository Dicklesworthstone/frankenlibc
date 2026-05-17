//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares the
//! legacy singular `underlying_lib_function` field, it must contain
//! at least one `::` separator — i.e. it's a Rust-style path
//! (bd-pcvbm). Mirrors bd-wmjs7's rule for the plural form. Catches
//! placeholders like `TODO` or bare crate names.

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
fn cli_contract_singular_underlying_lib_function_is_rust_path_when_present() -> TestResult {
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
        let Some(singular) = manifest
            .get("underlying_lib_function")
            .and_then(Value::as_str)
        else {
            continue;
        };
        checked += 1;
        if !looks_like_rust_path(singular) {
            violations.push(format!(
                "{name}: underlying_lib_function `{singular}` is not a Rust path (must contain `::`, no leading/trailing `::` or whitespace)"
            ));
        }
    }

    assert!(
        checked >= 5,
        "expected at least 5 manifests with singular underlying_lib_function; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} singular underlying_lib_function path violation(s):\n  {}",
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
    assert!(!looks_like_rust_path(""));
    assert!(!looks_like_rust_path("foo"));
    assert!(!looks_like_rust_path("::foo"));
    assert!(!looks_like_rust_path("foo::"));
    assert!(!looks_like_rust_path("foo bar::baz"));
}
