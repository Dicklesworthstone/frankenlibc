//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares a `source_commit` field that is a
//! lowercase hex string of length 7..=40 (a valid git short or full
//! object id) (bd-s4mst). Catches placeholder strings like `TBD`,
//! `WIP`, full commit messages accidentally pasted in, or non-hex
//! drift.

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

fn is_valid_git_object_id(s: &str) -> bool {
    let len = s.len();
    if !(7..=40).contains(&len) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[test]
fn every_cli_contract_manifest_source_commit_is_valid_hex() -> TestResult {
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
        match manifest.get("source_commit").and_then(Value::as_str) {
            Some(s) if is_valid_git_object_id(s) => {}
            Some(other) => violations.push(format!(
                "{name}: source_commit `{other}` is not a lowercase hex string of length 7..=40"
            )),
            None => violations.push(format!("{name}: missing source_commit field")),
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest source_commit violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn git_object_id_validator_handles_canonical_forms() {
    assert!(is_valid_git_object_id("abc1234"));
    assert!(is_valid_git_object_id(
        "0123456789abcdef0123456789abcdef01234567"
    ));
    assert!(!is_valid_git_object_id("abc123"));
    assert!(!is_valid_git_object_id(
        "0123456789abcdef0123456789abcdef012345678"
    ));
    assert!(!is_valid_git_object_id("ABC1234"));
    assert!(!is_valid_git_object_id("TBD"));
    assert!(!is_valid_git_object_id(""));
    assert!(!is_valid_git_object_id("abc1234x"));
}
