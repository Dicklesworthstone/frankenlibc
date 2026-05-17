//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `subcommand_name` matches `^[a-z0-9_-]+$` (bd-c8rbc). Restricts
//! the subcommand name to the argv-safe canonical charset — no
//! uppercase, no whitespace, no shell metacharacters. Catches drift
//! to names like `Foo`, `bar.baz`, or `do thing` that would break
//! tab-completion, shell quoting, or canonical invocation.

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

fn is_canonical_charset(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

#[test]
fn every_cli_contract_subcommand_name_uses_canonical_charset() -> TestResult {
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
        let Some(s) = manifest.get("subcommand_name").and_then(Value::as_str) else {
            continue;
        };
        if !is_canonical_charset(s) {
            violations.push(format!(
                "{name}: subcommand_name `{s}` contains chars outside [a-z0-9_-]"
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
            "{} subcommand_name charset violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn charset_detector_handles_canonical_forms() {
    assert!(is_canonical_charset("foo"));
    assert!(is_canonical_charset("foo_bar"));
    assert!(is_canonical_charset("foo-bar"));
    assert!(is_canonical_charset("foo_bar_42"));
    assert!(!is_canonical_charset(""));
    assert!(!is_canonical_charset("Foo"));
    assert!(!is_canonical_charset("foo bar"));
    assert!(!is_canonical_charset("foo.bar"));
}
