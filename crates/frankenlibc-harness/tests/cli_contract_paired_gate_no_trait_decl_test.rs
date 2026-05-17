//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares a trait (bd-7xjbo).
//! Paired CLI contract gates should stay as direct assertion code;
//! trait declarations indicate production abstractions or
//! over-engineering that belongs outside the gate file.

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

fn contains_trait_declaration(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("trait ") || trimmed.starts_with("pub trait ")
    })
}

#[test]
fn no_paired_gate_test_declares_trait() -> TestResult {
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
        if contains_trait_declaration(&body) {
            violations.push(format!(
                "{stem}: declares a trait (abstractions belong outside the gate file)"
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
            "{} paired gate trait declaration violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn trait_declaration_detector_handles_line_starts_only() {
    assert!(contains_trait_declaration("trait GateHelper {}"));
    assert!(contains_trait_declaration("    pub trait GateHelper {}"));
    assert!(!contains_trait_declaration(
        "let text = \"trait GateHelper\";"
    ));
    assert!(!contains_trait_declaration("struct TraitLike;"));
}
