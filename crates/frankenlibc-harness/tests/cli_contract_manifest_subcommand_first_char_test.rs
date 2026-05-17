//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `subcommand_name` starts with a lowercase ASCII letter (bd-1zd89).
//! Catches subcommand names with leading digits, symbols, or
//! whitespace — all of which would break canonical argv invocation.

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

#[test]
fn every_cli_contract_subcommand_name_starts_with_lowercase_letter() -> TestResult {
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
            violations.push(format!("{name}: missing subcommand_name"));
            checked += 1;
            continue;
        };
        match s.chars().next() {
            Some(c) if c.is_ascii_lowercase() => {}
            Some(c) => violations.push(format!(
                "{name}: subcommand_name `{s}` starts with `{c}` (must be lowercase ASCII letter)"
            )),
            None => violations.push(format!("{name}: subcommand_name is empty")),
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} subcommand_name first-char violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
