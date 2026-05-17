//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` imports `serde::Deserialize`
//! or derives `Deserialize` for structured deserialization (bd-eb661).
//! Gates work at the raw `serde_json::Value` level for resilience to
//! schema drift — typed deserialization would fail loudly on every
//! manifest extension, defeating the purpose of an evolving v1
//! schema with optional fields.

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

fn references_serde_deserialize(body: &str) -> bool {
    let direct_import = ["use serde", "::Deserialize"].concat();
    let plain_derive = ["#[derive(", "Deserialize"].concat();
    let qualified_derive = ["#[derive(serde", "::Deserialize"].concat();
    let non_comment_body = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    if non_comment_body.contains(&direct_import) {
        return true;
    }
    if non_comment_body.contains(&plain_derive) || non_comment_body.contains(&qualified_derive) {
        return true;
    }
    for line in non_comment_body.lines() {
        let t = line.trim();
        if t.starts_with("use serde::{") && t.contains(&["De", "serialize"].concat()) {
            return true;
        }
    }
    false
}

#[test]
fn no_paired_gate_test_imports_serde_deserialize() -> TestResult {
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
        if references_serde_deserialize(&body) {
            violations.push(format!(
                "{stem}: references typed deserialization (gates should use raw Value)"
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
            "{} paired gate typed deserialization violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn deserialize_detector_handles_canonical_forms() {
    let direct_import = ["use serde", "::Deserialize;"].concat();
    let grouped_import = ["use serde::{", "Deserialize, Serialize};"].concat();
    let plain_derive = ["#[derive(", "Deserialize)]"].concat();
    let qualified_derive = ["#[derive(serde", "::Deserialize, Debug)]"].concat();
    assert!(references_serde_deserialize(&direct_import));
    assert!(references_serde_deserialize(&grouped_import));
    assert!(references_serde_deserialize(&plain_derive));
    assert!(references_serde_deserialize(&qualified_derive));
    assert!(!references_serde_deserialize("use serde_json::Value;"));
    assert!(references_serde_deserialize(
        &["use serde::{Serialize, ", "Deserialize};"].concat()
    ));
    assert!(!references_serde_deserialize(
        "// Deserialize is fine in comments"
    ));
}
