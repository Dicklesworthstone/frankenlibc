//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest has
//! a corresponding paired gate test under `crates/frankenlibc-harness/tests/`
//! (bd-9ctp1). This catches orphan CLI contract manifests that document a
//! subcommand without a test file enforcing the contract.

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

fn paired_gate_test_name(manifest_name: &str) -> TestResult<String> {
    manifest_name
        .strip_suffix(".v1.json")
        .map(|stem| format!("{stem}_test.rs"))
        .ok_or_else(|| format!("{manifest_name}: expected .v1.json suffix"))
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
        let test_name = paired_gate_test_name(name)?;
        let test_path = tests_dir.join(&test_name);
        if !test_path.is_file() {
            violations.push(format!(
                "{name}: missing paired gate test `{test_name}` under {}",
                tests_dir.display()
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest paired-gate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn paired_gate_test_name_maps_manifest_basename() -> TestResult {
    assert_eq!(
        paired_gate_test_name("decode_evidence_cli_contract.v1.json")?,
        "decode_evidence_cli_contract_test.rs"
    );
    assert!(paired_gate_test_name("decode_evidence_cli_contract.json").is_err());
    Ok(())
}
