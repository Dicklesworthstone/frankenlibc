//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` references randomness
//! sources (`rand` crate, `::random`, `::rng`) (bd-gkfwy). Paired
//! gates must be deterministic conformance evidence; non-determinism
//! makes CI flaky and hides real regressions behind apparent
//! noise. Any required randomness must live inside the harness
//! binary with a deterministic seed surfaced as a CLI flag.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const FORBIDDEN: &[&str] = &["rand::", "::random", "::rng", "Rng::"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn no_paired_gate_test_references_randomness() -> TestResult {
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
        let non_comment_body = body
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for needle in FORBIDDEN {
            if non_comment_body.contains(needle) {
                violations.push(format!(
                    "{stem}: references `{needle}` (gates must be deterministic)"
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
            "{} paired gate randomness violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
