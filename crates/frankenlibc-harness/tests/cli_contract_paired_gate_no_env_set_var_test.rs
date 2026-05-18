//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` mutates the test-process
//! environment with `std::env::set_var` or `set_var(` (bd-wid37).
//! Paired CLI contract gates run under Cargo's parallel test runner;
//! process-global environment mutation creates order dependencies that
//! make conformance evidence nondeterministic.

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

fn contains_process_env_mutation(body: &str) -> bool {
    let full_path = ["std::env::", "set", "_var"].concat();
    let module_path = ["env::", "set", "_var"].concat();
    let call = ["set", "_var("].concat();
    body.lines().any(|line| {
        let code = line.split("//").next().unwrap_or("");
        code.contains(&full_path) || code.contains(&module_path) || code.contains(&call)
    })
}

#[test]
fn no_paired_gate_test_mutates_process_environment() -> TestResult {
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
        if contains_process_env_mutation(&body) {
            violations.push(format!(
                "{stem}: contains `set_var` process-environment mutation"
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
            "{} paired gate env-mutation violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn env_set_var_detector_handles_canonical_forms() {
    let std_call = [
        "std::env::",
        "set",
        "_var(\"FRANKENLIBC_MODE\", \"hardened\");",
    ]
    .concat();
    let env_call = ["env::", "set", "_var(\"A\", \"B\");"].concat();
    let bare_call = ["set", "_var(\"A\", \"B\");"].concat();
    let comment_call = ["// std::env::", "set", "_var(\"A\", \"B\");"].concat();
    assert!(contains_process_env_mutation(&std_call));
    assert!(contains_process_env_mutation(&env_call));
    assert!(contains_process_env_mutation(&bare_call));
    assert!(!contains_process_env_mutation(
        "Command::new(\"env\").arg(\"A=B\");"
    ));
    assert!(!contains_process_env_mutation(
        "let var_name = \"FRANKENLIBC_MODE\";"
    ));
    assert!(!contains_process_env_mutation(&comment_call));
}
