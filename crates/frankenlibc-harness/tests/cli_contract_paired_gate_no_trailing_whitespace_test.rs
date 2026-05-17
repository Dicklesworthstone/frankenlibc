//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` has trailing whitespace on
//! any line (bd-eqs8c). Catches sloppy edits that introduce stray
//! spaces or tabs at end-of-line, producing diff noise.

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

fn lines_with_trailing_whitespace(body: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    for (i, line) in body.lines().enumerate() {
        if line.ends_with(' ') || line.ends_with('\t') {
            hits.push(i + 1);
        }
    }
    hits
}

#[test]
fn no_paired_gate_test_has_trailing_whitespace() -> TestResult {
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
        let hits = lines_with_trailing_whitespace(&body);
        if !hits.is_empty() {
            violations.push(format!(
                "{stem}: {} line(s) with trailing whitespace: {hits:?}",
                hits.len()
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
            "{} paired gate trailing-whitespace violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn trailing_whitespace_detector_handles_canonical_forms() {
    assert_eq!(
        lines_with_trailing_whitespace("foo\nbar\n"),
        Vec::<usize>::new()
    );
    assert_eq!(lines_with_trailing_whitespace("foo \nbar"), vec![1]);
    assert_eq!(lines_with_trailing_whitespace("foo\nbar\t"), vec![2]);
    assert_eq!(lines_with_trailing_whitespace(""), Vec::<usize>::new());
}
