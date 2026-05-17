//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` resolves the conformance
//! manifest directory via the canonical `.join("tests")
//! .join("conformance")` 2-step join pattern (bd-fp9zn). Catches
//! gates that hardcode the absolute path, fuse it into a single
//! `.join("tests/conformance")`, or skip the canonical helper.

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

fn uses_canonical_conformance_join(body: &str) -> bool {
    body.contains("join(\"tests\")") && body.contains("join(\"conformance\")")
}

#[test]
fn every_paired_gate_test_uses_canonical_conformance_join() -> TestResult {
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
        if !uses_canonical_conformance_join(&body) {
            violations.push(format!(
                "{stem}: does not use canonical .join(\"tests\").join(\"conformance\") pattern"
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
            "{} paired gate canonical-join violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn canonical_conformance_join_detector_handles_canonical_forms() {
    assert!(uses_canonical_conformance_join(
        "root.join(\"tests\").join(\"conformance\")"
    ));
    assert!(uses_canonical_conformance_join(
        "let dir = ws.join(\"tests\").join(\"conformance\");"
    ));
    assert!(!uses_canonical_conformance_join(
        "join(\"tests/conformance\")"
    ));
    assert!(!uses_canonical_conformance_join("join(\"tests\")"));
    assert!(!uses_canonical_conformance_join(""));
}
