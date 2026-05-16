//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` has a corresponding `*_cli_contract_test.rs`
//! file under `crates/frankenlibc-harness/tests/` (bd-9ctp1). Catches
//! orphan manifests that were generated without a paired gate, which
//! is a common drift mode when manifests are batch-retrofitted but
//! gate tests are added one-at-a-time.

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
fn every_cli_contract_manifest_has_matching_paired_gate_test() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let basename = name.strip_suffix(".v1.json").expect("checked above");
        let expected_test = tests_dir.join(format!("{basename}_test.rs"));
        if !expected_test.exists() {
            violations.push(format!("{name}: no paired gate test at {expected_test:?}"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} orphan cli_contract manifest(s) without paired gate test:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
