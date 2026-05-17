//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` starts with a UTF-8 BOM
//! (bytes EF BB BF) (bd-i7h06). Editor-introduced BOMs are invisible
//! in most viewers but break rustfmt, some lint tools, and POSIX
//! `head -n1` style processing.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn no_paired_gate_test_starts_with_utf8_bom() -> TestResult {
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
        let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if bytes.starts_with(UTF8_BOM) {
            violations.push(format!("{stem}: starts with UTF-8 BOM"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate UTF-8 BOM violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
