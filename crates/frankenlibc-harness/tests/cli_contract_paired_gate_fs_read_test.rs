//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` must reference
//! `fs::read_to_string` or `fs::read(` (the canonical pattern for
//! loading the matching manifest from disk at test time) (bd-8xars).
//! Catches gate tests that mock the manifest content via inline
//! literals or load it from a non-canonical location.

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

fn references_canonical_fs_read(body: &str) -> bool {
    body.contains("fs::read_to_string") || body.contains("fs::read(")
}

#[test]
fn every_paired_gate_test_references_canonical_fs_read() -> TestResult {
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
        // Self-referential meta-gates iterate the conformance directory and
        // use their own read patterns.
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !references_canonical_fs_read(&body) {
            violations.push(format!(
                "{stem}: does not reference `fs::read_to_string` or `fs::read(` (manifest must be loaded from disk)"
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
            "{} paired gate test fs::read violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn fs_read_detector_handles_canonical_layouts() {
    assert!(references_canonical_fs_read(
        "let body = std::fs::read_to_string(&path)?;"
    ));
    assert!(references_canonical_fs_read(
        "use std::fs;\nlet bytes = fs::read(&path)?;"
    ));
    assert!(!references_canonical_fs_read(
        "let body = include_str!(\"../manifest.json\");"
    ));
    assert!(!references_canonical_fs_read(
        "let body = MANIFEST_LITERAL;"
    ));
}
