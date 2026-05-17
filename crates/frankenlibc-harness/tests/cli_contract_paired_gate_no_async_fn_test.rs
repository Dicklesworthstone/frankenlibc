//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares an `async fn`
//! (bd-7w5h5). Paired gates are synchronous Command spawners; an
//! `async fn` would require a runtime (tokio/async-std/etc.) and
//! indicate misuse of the canonical gate template. The synchronous
//! `#[test] fn name() -> TestResult` shape is the only supported
//! form.

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
fn no_paired_gate_test_declares_async_fn() -> TestResult {
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
        if body.contains("async fn") {
            violations.push(format!(
                "{stem}: declares `async fn` (paired gates must be synchronous)"
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
            "{} paired gate `async fn` violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
