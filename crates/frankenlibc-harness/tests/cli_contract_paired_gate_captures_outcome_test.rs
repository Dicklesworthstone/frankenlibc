//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` invokes at least one of
//! `.output(` or `.status(` (bd-5p69l). Confirms the gate captures
//! the spawned binary's outcome — exit status or stdout/stderr —
//! rather than spawning the binary with `.spawn()` and ignoring the
//! result (which would prove only that the binary exists, not that
//! the contract holds).

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
fn every_paired_gate_test_captures_outcome() -> TestResult {
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
        if !body.contains(".output(") && !body.contains(".status(") {
            violations.push(format!(
                "{stem}: invokes neither .output() nor .status() (does not capture spawned outcome)"
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
            "{} paired gate outcome-capture violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
