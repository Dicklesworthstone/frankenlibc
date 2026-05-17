//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` invokes `set_var`
//! (`std::env::set_var`) (bd-wid37). Test-process env mutation is a
//! cross-test ordering hazard under cargo test's parallel runner —
//! one gate's env mutation leaks into other gates' Command spawns,
//! producing nondeterministic conformance evidence. Subcommand env
//! must be set via `Command::env` on the spawned child only.

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

fn contains_process_env_mutator(body: &str) -> bool {
    let needle = ["set", "_var"].concat();
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with("//") && trimmed.contains(&needle)
    })
}

#[test]
fn no_paired_gate_test_invokes_process_env_mutator() -> TestResult {
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
        if contains_process_env_mutator(&body) {
            violations.push(format!(
                "{stem}: contains process-environment mutation hazard"
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
            "{} paired gate process-environment mutation violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn process_env_mutator_detector_handles_canonical_spellings() {
    let mutation = ["set", "_var"].concat();
    assert!(contains_process_env_mutator(&format!(
        "std::env::{mutation}(\"A\", \"B\");"
    )));
    assert!(contains_process_env_mutator(&format!(
        "env::{mutation}(\"A\", \"B\");"
    )));
    assert!(!contains_process_env_mutator(&format!(
        "// std::env::{mutation}(\"A\", \"B\");"
    )));
    assert!(!contains_process_env_mutator(
        "Command::new(\"env\").arg(\"A=B\");"
    ));
}
