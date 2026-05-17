//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares a `#[deny(...)]`
//! or `#[forbid(...)]` attribute (bd-sici6). The workspace already
//! enforces lints at the workspace level; per-file lint policy in
//! a test gate indicates either redundant configuration or a hack
//! to escape from a workspace-level allow. Both cases corrode the
//! single-source-of-truth lint policy.

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

fn declares_deny_or_forbid(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("#[deny(") || trimmed.starts_with("#[forbid(")
    })
}

#[test]
fn no_paired_gate_test_uses_deny_or_forbid_attribute() -> TestResult {
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
        if declares_deny_or_forbid(&body) {
            violations.push(format!(
                "{stem}: declares `#[deny(...)]` or `#[forbid(...)]` (use workspace-level lint policy)"
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
            "{} paired gate deny/forbid violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn deny_forbid_detector_handles_canonical_forms() {
    assert!(declares_deny_or_forbid("#[deny(warnings)]"));
    assert!(declares_deny_or_forbid("    #[forbid(unsafe_code)]"));
    assert!(!declares_deny_or_forbid("// #[deny(...)] comment"));
    assert!(!declares_deny_or_forbid("#[allow(dead_code)]"));
    assert!(!declares_deny_or_forbid("fn t() {}"));
}
