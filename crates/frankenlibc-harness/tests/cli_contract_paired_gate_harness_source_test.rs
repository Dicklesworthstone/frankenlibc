//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` must reference the string
//! `harness.rs` (the canonical assertion that the gate inspects the
//! harness binary's source for Subcommand registration) (bd-u9p95).
//! Catches gate tests that mock the source-registration check or skip
//! it entirely.

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
fn every_paired_gate_test_references_harness_rs_source_file() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_count = 0usize;
    let mut checked = 0usize;
    const LEGACY_GATES_WITHOUT_HARNESS_REF: &[&str] = &[
        "conformance_matrix_case_cli_contract_test.rs",
        "conformance_matrix_cli_contract_test.rs",
        "shadow_run_cli_contract_test.rs",
    ];
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        // Self-referential meta-gates iterate the conformance directory and
        // do not need to reach into harness.rs.
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !body.contains("harness.rs") {
            if LEGACY_GATES_WITHOUT_HARNESS_REF.contains(&stem) {
                legacy_count += 1;
            } else {
                violations.push(format!(
                    "{stem}: does not reference `harness.rs` (source-registration assertion missing)"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate test harness.rs reference violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }

    if legacy_count > LEGACY_GATES_WITHOUT_HARNESS_REF.len() {
        return Err(format!(
            "legacy gate count without harness.rs reference rose to {legacy_count} (ceiling: {})",
            LEGACY_GATES_WITHOUT_HARNESS_REF.len()
        ));
    }
    Ok(())
}
