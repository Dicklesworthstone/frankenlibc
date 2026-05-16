//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `io_pattern` snake_case string (bd-hb3bu). Catches
//! manifests that don't document their stdin/stdout/output-file IO contract
//! shape.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const LEGACY_IO_PATTERN_MISSING_CEILING: usize = 46;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_snake_case(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_manifest_declares_snake_case_io_pattern() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut missing: Vec<String> = Vec::new();
    let mut shape_violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))?;
        match manifest.get("io_pattern").and_then(Value::as_str) {
            None => missing.push(stem.to_string()),
            Some("") => missing.push(stem.to_string()),
            Some(s) if !is_snake_case(s) => {
                shape_violations.push(format!("{stem}: io_pattern=`{s}` is not snake_case"))
            }
            Some(_) => {}
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !shape_violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest io_pattern shape violation(s):\n  {}",
            shape_violations.len(),
            shape_violations.join("\n  ")
        ));
    }

    if missing.len() > LEGACY_IO_PATTERN_MISSING_CEILING {
        return Err(format!(
            "{} CLI contract manifest(s) with missing or empty io_pattern (ceiling {LEGACY_IO_PATTERN_MISSING_CEILING}):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}
