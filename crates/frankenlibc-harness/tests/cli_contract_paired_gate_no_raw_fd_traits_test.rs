//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` mentions raw file descriptor
//! traits (`AsRawFd`, `IntoRawFd`, `FromRawFd`) (bd-q4sri).
//! Paired gates spawn processes through `Command` and observe captured
//! output; raw-fd plumbing belongs in the harness binary or a sibling
//! crate, not in the paired contract gate files.

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

fn contains_forbidden_fd_trait_name(body: &str) -> bool {
    let as_raw = ["As", "RawFd"].concat();
    let into_raw = ["Into", "RawFd"].concat();
    let from_raw = ["From", "RawFd"].concat();
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        let code = trimmed.split("//").next().unwrap_or("").trim_end();
        !trimmed.starts_with("//")
            && (code.contains(&as_raw) || code.contains(&into_raw) || code.contains(&from_raw))
    })
}

#[test]
fn no_paired_gate_test_mentions_raw_fd_traits() -> TestResult {
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
        if contains_forbidden_fd_trait_name(&body) {
            violations.push(format!(
                "{stem}: mentions raw file descriptor traits (raw-fd plumbing belongs outside the gate file)"
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
            "{} paired gate raw-fd trait violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn raw_fd_trait_detector_handles_canonical_names() {
    let as_raw = ["As", "RawFd"].concat();
    let into_raw = ["Into", "RawFd"].concat();
    let from_raw = ["From", "RawFd"].concat();
    assert!(contains_forbidden_fd_trait_name(&format!(
        "use std::os::fd::{as_raw};"
    )));
    assert!(contains_forbidden_fd_trait_name(&format!(
        "use std::os::fd::{into_raw};"
    )));
    assert!(contains_forbidden_fd_trait_name(&format!(
        "use std::os::fd::{from_raw};"
    )));
    assert!(!contains_forbidden_fd_trait_name(&format!(
        "// use std::os::fd::{as_raw};"
    )));
    assert!(!contains_forbidden_fd_trait_name(&format!(
        "let fd = 1; // {into_raw}"
    )));
    assert!(!contains_forbidden_fd_trait_name(
        "Command::new(\"frankenlibc-harness\");"
    ));
}
