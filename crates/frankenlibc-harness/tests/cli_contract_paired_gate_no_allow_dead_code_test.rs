//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares an
//! `#[allow(dead_code)]` attribute (bd-j60g5). Dead code in a gate
//! test is real dead code (leftover helpers, abandoned assertions);
//! suppressing the lint hides stale stubs instead of pruning them.

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

fn count_allow_dead_code_attributes(body: &str) -> usize {
    body.lines()
        .filter(|line| {
            let t = line.trim_start();
            t.starts_with("#[allow(dead_code") || t.starts_with("#![allow(dead_code")
        })
        .count()
}

#[test]
fn no_paired_gate_test_declares_allow_dead_code() -> TestResult {
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
        let count = count_allow_dead_code_attributes(&body);
        if count > 0 {
            violations.push(format!(
                "{stem}: declares {count} `#[allow(dead_code)]` attribute(s)"
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
            "{} paired gate `#[allow(dead_code)]` violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn allow_dead_code_counter_handles_canonical_forms() {
    assert_eq!(count_allow_dead_code_attributes("#[allow(dead_code)]"), 1);
    assert_eq!(
        count_allow_dead_code_attributes("  #[allow(dead_code, unused)]"),
        1
    );
    assert_eq!(count_allow_dead_code_attributes("#![allow(dead_code)]"), 1);
    assert_eq!(
        count_allow_dead_code_attributes("// #[allow(dead_code)]"),
        0
    );
    assert_eq!(count_allow_dead_code_attributes("fn x() {}"), 0);
}
