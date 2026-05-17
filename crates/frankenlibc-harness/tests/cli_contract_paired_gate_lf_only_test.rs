//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` contains CRLF (\r\n) line
//! endings (bd-wcqh2). LF-only is the project's POSIX convention;
//! CRLF lines slip in from Windows editors and break rustfmt's diff
//! output and some downstream tooling.

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

fn count_crlf_lines(bytes: &[u8]) -> usize {
    let mut n = 0usize;
    for window in bytes.windows(2) {
        if window == [b'\r', b'\n'] {
            n += 1;
        }
    }
    n
}

#[test]
fn no_paired_gate_test_contains_crlf_line_endings() -> TestResult {
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
        let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let n = count_crlf_lines(&bytes);
        if n > 0 {
            violations.push(format!("{stem}: {n} CRLF line ending(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate CRLF violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn crlf_counter_handles_canonical_forms() {
    assert_eq!(count_crlf_lines(b"foo\nbar\n"), 0);
    assert_eq!(count_crlf_lines(b"foo\r\nbar\r\n"), 2);
    assert_eq!(count_crlf_lines(b"foo\rbar"), 0);
    assert_eq!(count_crlf_lines(b""), 0);
}
