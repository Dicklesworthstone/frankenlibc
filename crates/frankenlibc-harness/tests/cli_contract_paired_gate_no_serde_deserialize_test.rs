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
    if body.contains("use serde::Deserialize") {
        return true;
    }
    if body.contains("#[derive(Deserialize") || body.contains("#[derive(serde::Deserialize") {
        return true;
    }
    // `use serde::{...Deserialize...}` aggregated import
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("use serde::{") && t.contains("Deserialize") {
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
                "{stem}: references serde::Deserialize (gates should use raw Value, not typed deserialization)"
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
            "{} paired gate serde::Deserialize violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn deserialize_detector_handles_canonical_forms() {
    assert!(references_serde_deserialize("use serde::Deserialize;"));
    assert!(references_serde_deserialize(
        "use serde::{Deserialize, Serialize};"
    ));
    assert!(references_serde_deserialize("#[derive(Deserialize)]"));
    assert!(references_serde_deserialize(
        "#[derive(serde::Deserialize, Debug)]"
    ));
    assert!(!references_serde_deserialize("use serde_json::Value;"));
    assert!(!references_serde_deserialize(
        "// Deserialize is fine in comments"
    ));
}
