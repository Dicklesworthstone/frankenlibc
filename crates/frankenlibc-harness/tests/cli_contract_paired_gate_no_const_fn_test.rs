//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares `const fn`
//! (bd-5oqtx). Paired CLI contract gates are runtime process
//! checks; compile-time helpers in those files make the gate harder
//! to audit and should live in the harness crate instead.

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

fn contains_forbidden_const_helper(body: &str) -> bool {
    let forbidden = ["const", " fn"].concat();
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        let code = trimmed.split("//").next().unwrap_or("").trim_end();
        !trimmed.starts_with("//") && code.contains(&forbidden)
    })
}

#[test]
fn no_paired_gate_test_declares_const_fn() -> TestResult {
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
        if contains_forbidden_const_helper(&body) {
            violations.push(format!(
                "{stem}: declares compile-time helper function (helpers belong outside the gate file)"
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
            "{} paired gate compile-time helper violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn const_fn_detector_handles_literal_declaration() {
    let forbidden_prefix = ["const", " fn"].concat();
    let forbidden_vis = ["pub(crate) const", " fn"].concat();
    assert!(contains_forbidden_const_helper(&format!(
        "{forbidden_prefix} workspace_root() -> PathBuf"
    )));
    assert!(contains_forbidden_const_helper(&format!(
        "{forbidden_vis} helper() -> usize"
    )));
    assert!(!contains_forbidden_const_helper(&format!(
        "// {forbidden_prefix} in a comment is documentation, not a declaration"
    )));
    assert!(!contains_forbidden_const_helper(&format!(
        "let x = 1; // {forbidden_prefix} inline comment"
    )));
    assert!(!contains_forbidden_const_helper(
        "fn workspace_root() -> TestResult<PathBuf>"
    ));
}
