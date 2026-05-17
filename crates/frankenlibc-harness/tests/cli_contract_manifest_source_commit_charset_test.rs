//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `source_commit` contains only lowercase hex characters
//! `[0-9a-f]` (bd-k9vu8). Catches mixed-case hex (which breaks
//! string-equality lookups against git's lowercase canonical form)
//! or non-hex characters entirely.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_lowercase_hex(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[test]
fn every_cli_contract_source_commit_is_lowercase_hex_only() -> TestResult {
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
        let Some(s) = manifest.get("source_commit").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing source_commit"));
            checked += 1;
            continue;
        };
        if !is_lowercase_hex(s) {
            violations.push(format!(
                "{name}: source_commit `{s}` contains non-lowercase-hex characters"
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
            "{} source_commit charset violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn lowercase_hex_validator_handles_canonical_forms() {
    assert!(is_lowercase_hex("abc1234"));
    assert!(is_lowercase_hex("0123456789abcdef"));
    assert!(!is_lowercase_hex(""));
    assert!(!is_lowercase_hex("ABC1234"));
    assert!(!is_lowercase_hex("g123456"));
    assert!(!is_lowercase_hex("abc 123"));
}
