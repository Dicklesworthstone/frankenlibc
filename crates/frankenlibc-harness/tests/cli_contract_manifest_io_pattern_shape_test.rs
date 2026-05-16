//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares an
//! `io_pattern`, the value is a snake_case identifier of at least
//! 10 characters (bd-7c6hh). The corpus has 37 unique io_patterns
//! today, all snake_case and descriptively long — a closed-set check
//! is impractical, but the shape rule catches placeholders like
//! `TODO`, `foo`, or PascalCase drift.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_IO_PATTERN_LEN: usize = 10;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_snake_case_descriptive(s: &str) -> bool {
    if s.len() < MIN_IO_PATTERN_LEN {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn every_cli_contract_io_pattern_is_snake_case_descriptive() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(io_pattern) = manifest.get("io_pattern").and_then(Value::as_str) else {
            continue;
        };
        if !is_snake_case_descriptive(io_pattern) {
            violations.push(format!(
                "{name}: io_pattern `{io_pattern}` is not snake_case-descriptive (min {MIN_IO_PATTERN_LEN} chars, lowercase + digits + underscores, first char lowercase)"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 io_pattern-bearing manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} io_pattern shape violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_descriptive_validator_handles_canonical_forms() {
    assert!(is_snake_case_descriptive(
        "output_file_single_jsonl_record_no_stdout"
    ));
    assert!(is_snake_case_descriptive(
        "jsonl_log_plus_json_report_no_stdout_jsonl"
    ));
    assert!(is_snake_case_descriptive("aaaaaaaaaa"));
    assert!(!is_snake_case_descriptive("short"));
    assert!(!is_snake_case_descriptive("TODOTODOTODOTODO"));
    assert!(!is_snake_case_descriptive("CamelCaseString"));
    assert!(!is_snake_case_descriptive("kebab-case-pattern"));
    assert!(!is_snake_case_descriptive("1leading_digit"));
    assert!(!is_snake_case_descriptive(""));
}
