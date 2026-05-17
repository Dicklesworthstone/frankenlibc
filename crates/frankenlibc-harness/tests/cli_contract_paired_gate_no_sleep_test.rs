//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` invokes `thread::sleep` or
//! `sleep(` (bd-6ru0e). Paired CLI contract gates exercise binary
//! subcommands deterministically — any `sleep()` would indicate a
//! fake/timing-based stub (waiting for a thing to happen instead of
//! asserting it deterministically) or test flakiness, both of which
//! corrode the CLI conformance evidence the paired gates provide.

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

fn contains_sleep_call(body: &str) -> bool {
    let forbidden = [["thread", "::sleep"].concat(), ["sleep", "("].concat()];
    let non_comment_body = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    forbidden
        .iter()
        .any(|needle| non_comment_body.contains(needle))
}

#[test]
fn no_paired_gate_test_invokes_sleep() -> TestResult {
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
        if contains_sleep_call(&body) {
            violations.push(format!(
                "{stem}: contains a sleep call (deterministic gates must not sleep)"
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
            "{} paired gate sleep-call violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn sleep_detector_handles_canonical_forms() {
    let thread_call = ["std::thread", "::sleep(Duration::from_secs(1));"].concat();
    let free_call = ["sleep", "(100);"].concat();
    assert!(contains_sleep_call(&thread_call));
    assert!(contains_sleep_call(&free_call));
    assert!(!contains_sleep_call("// no sleep here"));
    assert!(!contains_sleep_call("fn awake() {}"));
}
