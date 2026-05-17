//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` contains a `.unwrap()` call
//! (bd-tp45o). Gate tests must propagate errors via `TestResult`,
//! never via panic. `.unwrap()` strips the violation context and
//! makes regressions harder to triage.

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

fn count_unwrap_calls(body: &str) -> usize {
    body.matches(".unwrap()").count()
}

#[test]
fn no_paired_gate_test_contains_unwrap_call() -> TestResult {
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
        let count = count_unwrap_calls(&body);
        if count > 0 {
            violations.push(format!("{stem}: contains {count} `.unwrap()` call(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate test .unwrap() violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn unwrap_counter_handles_canonical_forms() {
    assert_eq!(count_unwrap_calls("x.unwrap()"), 1);
    assert_eq!(count_unwrap_calls("a.unwrap().unwrap()"), 2);
    assert_eq!(count_unwrap_calls("// safe via .unwrap()"), 1);
    assert_eq!(count_unwrap_calls("ok"), 0);
}
