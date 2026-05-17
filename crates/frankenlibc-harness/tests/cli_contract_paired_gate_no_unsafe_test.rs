//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` contains the keyword
//! `unsafe` (bd-1mgww). Paired gates exercise the harness binary
//! via Command spawn at the process boundary — they have no
//! business invoking raw FFI, transmutes, or pointer ops in test
//! code. Presence of `unsafe` indicates either misplaced low-level
//! probe logic (which belongs in a different crate's tests) or
//! copy-paste pollution from production code.

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
fn no_paired_gate_test_contains_low_level_keyword() -> TestResult {
    let forbidden = ["un", "safe"].concat();
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
        let non_comment_body = body
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        if non_comment_body.contains(&forbidden) {
            violations.push(format!(
                "{stem}: contains keyword `{forbidden}` (paired gates must not contain low-level code)"
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
            "{} paired gate `{}` keyword violation(s):\n  {}",
            violations.len(),
            forbidden,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
