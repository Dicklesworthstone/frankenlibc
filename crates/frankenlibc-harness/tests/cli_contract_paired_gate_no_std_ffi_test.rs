//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` imports `std::ffi`
//! (bd-dk9ou). Paired gates spawn processes via `std::process::Command`
//! at the `OsStr` boundary; importing `std::ffi` (CStr/CString/
//! OsStr/OsString) indicates misplaced FFI manipulation that belongs
//! in the harness binary or a sibling crate, not in the conformance
//! gate file.

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

#[test]
fn no_paired_gate_test_imports_std_ffi() -> TestResult {
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
        if body.contains("std::ffi") {
            violations.push(format!(
                "{stem}: imports `std::ffi` (FFI manipulation belongs outside the gate file)"
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
            "{} paired gate `std::ffi` import violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
