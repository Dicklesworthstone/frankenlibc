//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` references
//! `Box<dyn Error>` / `Box<dyn std::error::Error>` (or their
//! `Box::<...>` turbofish variants) (bd-qv3j1). Gates standardize on
//! `TestResult<T, String>` for structured error propagation; boxed
//! trait objects defeat the goal of consistent, greppable error
//! formatting in CI.

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

fn references_box_dyn_error(body: &str) -> bool {
    let forbidden = [
        ["Box<dyn ", "Error"].concat(),
        ["Box::<dyn ", "Error"].concat(),
        ["Box<dyn std::error::", "Error"].concat(),
        ["Box::<dyn std::error::", "Error"].concat(),
    ];
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
fn no_paired_gate_test_uses_box_dyn_error() -> TestResult {
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
        if references_box_dyn_error(&body) {
            violations.push(format!(
                "{stem}: references a boxed error trait object (use TestResult<T, String> instead)"
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
            "{} paired gate boxed error trait object violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn box_dyn_error_detector_handles_canonical_forms() {
    assert!(references_box_dyn_error(&["Box<dyn ", "Error>"].concat()));
    assert!(references_box_dyn_error(
        &["Box<dyn ", "Error + Send>"].concat()
    ));
    assert!(references_box_dyn_error(
        &["Box::<dyn ", "Error>::new(x)"].concat()
    ));
    assert!(references_box_dyn_error(
        &["Box<dyn std::error::", "Error>"].concat()
    ));
    assert!(references_box_dyn_error(
        &["Box::<dyn std::error::", "Error>"].concat()
    ));
    assert!(!references_box_dyn_error("Box<dyn Trait>"));
    assert!(!references_box_dyn_error("Result<T, String>"));
    assert!(!references_box_dyn_error("ok"));
}
