//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` is at most 800 lines (bd-b4gh4).
//! Catches monolithic gate tests that should be split into focused
//! per-invariant files. Largest current paired gate is ~520 lines;
//! the 800 ceiling absorbs natural growth while triggering on real
//! "everything goes here" sprawl.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MAX_PAIRED_GATE_LINES: usize = 800;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn count_lines(body: &str) -> usize {
    if body.is_empty() {
        0
    } else if body.ends_with('\n') {
        body.matches('\n').count()
    } else {
        body.matches('\n').count() + 1
    }
}

#[test]
fn every_paired_gate_test_within_line_ceiling() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut largest_seen = (0usize, String::new());
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
        let lines = count_lines(&body);
        if lines > largest_seen.0 {
            largest_seen = (lines, stem.to_string());
        }
        if lines > MAX_PAIRED_GATE_LINES {
            violations.push(format!(
                "{stem}: {lines} lines exceeds ceiling {MAX_PAIRED_GATE_LINES}"
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
            "{} paired gate line-ceiling violation(s) (ceiling={MAX_PAIRED_GATE_LINES}, largest seen={} @ {} lines):\n  {}",
            violations.len(),
            largest_seen.1,
            largest_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn line_counter_handles_canonical_forms() {
    assert_eq!(count_lines(""), 0);
    assert_eq!(count_lines("a"), 1);
    assert_eq!(count_lines("a\n"), 1);
    assert_eq!(count_lines("a\nb"), 2);
    assert_eq!(count_lines("a\nb\n"), 2);
    assert_eq!(count_lines("\n"), 1);
}
