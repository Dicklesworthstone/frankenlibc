//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` must declare at least 3 `#[test]`
//! functions (manifest validation + source registration + at least one
//! behavioral check) (bd-9zswz). Catches stub gate tests with too-narrow
//! coverage. Self-referential meta-gates may have fewer (often just 1-2).

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MIN_TEST_FUNCTIONS_PER_PAIRED_GATE: usize = 3;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn count_test_attributes(body: &str) -> usize {
    body.lines()
        .filter(|line| line.trim_start().starts_with("#[test]"))
        .count()
}

#[test]
fn every_paired_gate_test_declares_at_least_three_test_functions() -> TestResult {
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
        // Self-referential meta-gates are allowed to have fewer tests.
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let count = count_test_attributes(&body);
        if count < MIN_TEST_FUNCTIONS_PER_PAIRED_GATE {
            violations.push(format!(
                "{stem}: declares {count} #[test] function(s) (minimum {MIN_TEST_FUNCTIONS_PER_PAIRED_GATE})"
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
            "{} paired gate test #[test] count violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn test_attribute_counter_handles_canonical_layouts() {
    let body = "#[test]\nfn a() {}\n#[test]\nfn b() {}\n  #[test]\n  fn c() {}\n";
    assert_eq!(count_test_attributes(body), 3);
    let no_tests = "fn helper() {}\n// #[test]\n";
    assert_eq!(count_test_attributes(no_tests), 0);
}
