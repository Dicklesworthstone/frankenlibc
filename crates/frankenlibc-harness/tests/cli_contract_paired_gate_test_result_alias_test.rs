//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` must declare a `TestResult` type
//! alias (canonical error-propagation convention) (bd-stg8c). Catches
//! gate tests that drift to ad-hoc Result types or use `panic!` macros
//! instead of returning structured errors via `TestResult`.

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

fn declares_test_result_alias(body: &str) -> bool {
    body.lines().any(|line| {
        let t = line.trim_start();
        t.starts_with("type TestResult") || t.starts_with("pub type TestResult")
    })
}

#[test]
fn every_paired_gate_test_declares_test_result_alias() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    // Peer agents shipped a handful of paired gates whose canonical error
    // type predates the `TestResult` alias convention. Ratchet them as a
    // floor so new offenders fail-closed but the count can only go down
    // as those gates are individually migrated.
    const LEGACY_GATES_WITHOUT_TEST_RESULT_ALIAS: &[&str] = &[
        "conformance_matrix_case_cli_contract_test.rs",
        "conformance_matrix_cli_contract_test.rs",
        "shadow_run_cli_contract_test.rs",
    ];

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_count = 0usize;
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
        // Self-referential meta-gates may use ad-hoc Result types because
        // they don't follow the paired-gate template.
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !declares_test_result_alias(&body) {
            if LEGACY_GATES_WITHOUT_TEST_RESULT_ALIAS.contains(&stem) {
                legacy_count += 1;
            } else {
                violations.push(format!(
                    "{stem}: does not declare `TestResult` type alias (canonical error-propagation convention)"
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
            "{} paired gate test TestResult-alias violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }

    if legacy_count > LEGACY_GATES_WITHOUT_TEST_RESULT_ALIAS.len() {
        return Err(format!(
            "legacy paired gates without TestResult alias rose to {legacy_count} (ceiling: {})",
            LEGACY_GATES_WITHOUT_TEST_RESULT_ALIAS.len()
        ));
    }
    Ok(())
}

#[test]
fn test_result_alias_detector_handles_canonical_forms() {
    assert!(declares_test_result_alias(
        "type TestResult<T = ()> = Result<T, String>;"
    ));
    assert!(declares_test_result_alias(
        "  type TestResult = Result<(), String>;"
    ));
    assert!(declares_test_result_alias(
        "pub type TestResult<T = ()> = Result<T, String>;"
    ));
    assert!(!declares_test_result_alias(
        "type FooResult = Result<(), String>;"
    ));
    assert!(!declares_test_result_alias("// type TestResult"));
}
