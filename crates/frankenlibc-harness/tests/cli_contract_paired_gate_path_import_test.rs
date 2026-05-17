//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` imports `std::path::Path` or
//! `std::path::PathBuf` (or aggregates them via `use std::path::{...}`)
//! (bd-uxy3v). This pin enforces the canonical `workspace_root()`
//! helper signature returning `PathBuf` — catches drift to ad-hoc
//! `&str`/`String` path types that lose Path's cross-platform
//! semantics.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn imports_std_path(body: &str) -> bool {
    body.contains("use std::path::Path")
        || body.contains("use std::path::PathBuf")
        || body.contains("use std::path::{")
}

#[test]
fn every_paired_gate_test_imports_std_path() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !imports_std_path(&body) {
            violations.push(format!(
                "{stem}: does not import std::path::Path or PathBuf"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate std::path-import violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn path_import_detector_handles_canonical_forms() {
    assert!(imports_std_path("use std::path::Path;"));
    assert!(imports_std_path("use std::path::PathBuf;"));
    assert!(imports_std_path("use std::path::{Path, PathBuf};"));
    assert!(!imports_std_path("use std::fs;"));
    assert!(!imports_std_path("use serde_json::Value;"));
}
