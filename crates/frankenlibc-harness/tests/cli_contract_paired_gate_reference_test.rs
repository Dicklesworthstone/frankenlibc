//! Meta-gate: every paired `*_cli_contract_test.rs` gate file in
//! `crates/frankenlibc-harness/tests/` must contain a string literal naming
//! the matching `tests/conformance/<basename>_cli_contract.v1.json` manifest
//! (bd-5455c). Catches gate tests that drift to point at a different manifest
//! after a rename.

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
fn every_paired_gate_test_file_references_its_matching_manifest_basename() -> TestResult {
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
        // Self-referential meta-gates pass through the convention check
        // because they parse the conformance directory wholesale rather
        // than pointing at one specific manifest. The pattern they use is
        // `_cli_contract.v1.json` (no specific basename).
        if !stem.starts_with("cli_contract_") {
            let basename = stem.strip_suffix("_test.rs").expect("checked suffix above");
            let expected_substring = format!("{basename}.v1.json");
            let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
            if !body.contains(&expected_substring) {
                violations.push(format!(
                    "{stem}: does not reference its matching manifest `{expected_substring}`"
                ));
            }
            checked += 1;
        }
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate test manifest-reference violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
