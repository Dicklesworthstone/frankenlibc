//! Meta-gate (inverse of orphan-manifest): every paired
//! `*_cli_contract_test.rs` file under
//! `crates/frankenlibc-harness/tests/` has a corresponding
//! `*_cli_contract.v1.json` manifest under `tests/conformance/`
//! (bd-gw4ay). Catches orphan gate tests that were authored before
//! their manifest was generated, or that point at a deleted manifest
//! after a rename. Self-referential meta-gates (`cli_contract_*` and
//! `harness_subcommand_*` prefixes) are exempt.

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
fn every_paired_gate_test_has_matching_cli_contract_manifest() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let conformance_dir = root.join("tests").join("conformance");
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
        // Self-referential meta-gates iterate the conformance directory and
        // don't pair with a single manifest.
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let basename = stem.strip_suffix("_test.rs").expect("checked suffix above");
        let expected_manifest = conformance_dir.join(format!("{basename}.v1.json"));
        if !expected_manifest.exists() {
            violations.push(format!(
                "{stem}: no matching manifest at {expected_manifest:?}"
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
            "{} orphan paired gate test(s) without matching cli_contract manifest:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
