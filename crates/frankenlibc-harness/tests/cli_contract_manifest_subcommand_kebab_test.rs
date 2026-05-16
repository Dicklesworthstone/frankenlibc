//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares a non-empty `subcommand_name` field
//! whose value is canonical kebab-case (lowercase + digits + hyphens,
//! no leading/trailing/double hyphens) (bd-e1ji7). Catches drift to
//! snake_case, PascalCase, or whitespace-bearing subcommand names.

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

fn is_canonical_kebab(s: &str) -> bool {
    if s.is_empty() || s.starts_with('-') || s.ends_with('-') || s.contains("--") {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[test]
fn every_cli_contract_manifest_subcommand_name_is_kebab_case() -> TestResult {
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
        match manifest.get("subcommand_name").and_then(Value::as_str) {
            Some(s) if is_canonical_kebab(s) => {}
            Some(other) => violations.push(format!(
                "{name}: subcommand_name `{other}` is not canonical kebab-case"
            )),
            None => violations.push(format!("{name}: missing subcommand_name field")),
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest subcommand_name kebab violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn kebab_validator_handles_canonical_forms() {
    assert!(is_canonical_kebab("foo"));
    assert!(is_canonical_kebab("foo-bar"));
    assert!(is_canonical_kebab("foo-bar-baz"));
    assert!(is_canonical_kebab("h2o"));
    assert!(is_canonical_kebab("a1-b2"));
    assert!(!is_canonical_kebab(""));
    assert!(!is_canonical_kebab("-foo"));
    assert!(!is_canonical_kebab("foo-"));
    assert!(!is_canonical_kebab("foo--bar"));
    assert!(!is_canonical_kebab("FooBar"));
    assert!(!is_canonical_kebab("foo_bar"));
    assert!(!is_canonical_kebab("foo bar"));
}
