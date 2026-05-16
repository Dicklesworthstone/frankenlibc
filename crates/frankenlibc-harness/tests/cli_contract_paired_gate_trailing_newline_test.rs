//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` ends with a single trailing
//! newline (POSIX text-file rule) (bd-5e6o7). Catches files saved
//! without trailing newline that cause spurious "No newline at end of
//! file" diff noise.

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

fn ends_with_single_trailing_newline(body: &[u8]) -> bool {
    matches!(body.last(), Some(b'\n'))
}

#[test]
fn every_paired_gate_test_file_ends_with_trailing_newline() -> TestResult {
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
        let body = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !ends_with_single_trailing_newline(&body) {
            violations.push(format!(
                "{stem}: does not end with trailing newline (POSIX text-file rule)"
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
            "{} paired gate test trailing-newline violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn trailing_newline_detector_handles_canonical_forms() {
    assert!(ends_with_single_trailing_newline(b"fn main() {}\n"));
    assert!(ends_with_single_trailing_newline(b"\n"));
    assert!(!ends_with_single_trailing_newline(b"fn main() {}"));
    assert!(!ends_with_single_trailing_newline(b""));
}
