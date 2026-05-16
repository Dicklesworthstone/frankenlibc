//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! have a paired `crates/frankenlibc-harness/tests/<basename>_test.rs` gate
//! file. Prevents manifests committed without executable validation.

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
fn every_cli_contract_manifest_has_paired_gate_test_file() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");

    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let prefix = stem.strip_suffix(".v1.json").expect("checked suffix above");
        let gate_filename = format!("{prefix}_test.rs");
        let gate_path = tests_dir.join(&gate_filename);
        if !gate_path.exists() {
            missing.push(format!(
                "{stem} -> crates/frankenlibc-harness/tests/{gate_filename}"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !missing.is_empty() {
        return Err(format!(
            "{} CLI contract manifest(s) missing paired gate test:\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}
