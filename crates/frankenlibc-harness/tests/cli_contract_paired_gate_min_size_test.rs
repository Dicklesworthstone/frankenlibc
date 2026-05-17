//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` is at least 512 bytes
//! (bd-og4jr). Rules out truly skeletal gate files. The canonical
//! gate template (workspace_root helper + Command spawn + assertions)
//! is ~2KB; even the smallest real gate clears 1KB. A sub-512-byte
//! gate is almost certainly a stub or stripped-down placeholder.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MIN_BYTES: u64 = 512;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_paired_gate_test_meets_minimum_size() -> TestResult {
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
        let metadata = std::fs::metadata(&path).map_err(|e| format!("metadata {path:?}: {e}"))?;
        let size = metadata.len();
        if size < MIN_BYTES {
            violations.push(format!(
                "{stem}: {size} bytes (require >= {MIN_BYTES} — suspiciously small for a real gate)"
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
            "{} paired gate min-size violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
