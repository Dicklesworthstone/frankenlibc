//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `binary_target` is a snake_case identifier with length [1, 20]
//! (bd-eyanz). Catches binary_targets that drift to kebab-case,
//! whitespace, or absurdly long values (which break `cargo run -p`
//! / rch invocation paths).

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_BINARY_TARGET_LEN: usize = 1;
const MAX_BINARY_TARGET_LEN: usize = 20;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_snake_case_identifier(s: &str) -> bool {
    if !(MIN_BINARY_TARGET_LEN..=MAX_BINARY_TARGET_LEN).contains(&s.len()) {
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
fn every_cli_contract_binary_target_is_short_snake_case() -> TestResult {
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
        let Some(s) = manifest.get("binary_target").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing binary_target"));
            checked += 1;
            continue;
        };
        if !is_snake_case_identifier(s) {
            violations.push(format!(
                "{name}: binary_target `{s}` is not snake_case identifier of length [{MIN_BINARY_TARGET_LEN},{MAX_BINARY_TARGET_LEN}]"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} binary_target shape violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_identifier_validator_handles_canonical_forms() {
    assert!(is_snake_case_identifier("harness"));
    assert!(is_snake_case_identifier("a"));
    assert!(is_snake_case_identifier("frankenlibc_harness"));
    assert!(!is_snake_case_identifier(""));
    assert!(!is_snake_case_identifier("Harness"));
    assert!(!is_snake_case_identifier("harness-bin"));
    assert!(!is_snake_case_identifier("1harness"));
    assert!(!is_snake_case_identifier(
        "this_is_a_very_long_name_well_past_twenty"
    ));
}
