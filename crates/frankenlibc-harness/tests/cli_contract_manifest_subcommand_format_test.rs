//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest's
//! `subcommand_name` must be kebab-case (lowercase + hyphens + digits only,
//! no underscores, no leading/trailing dash, no double-dash) (bd-l9mf7).
//! Catches conventions drift before the binary fails clap parsing.

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

fn is_clap_kebab(s: &str) -> bool {
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
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))?;
        let name = manifest
            .get("subcommand_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !is_clap_kebab(name) {
            violations.push(format!(
                "{stem}: subcommand_name=`{name}` is not kebab-case"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract subcommand_name kebab-case violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn kebab_validator_accepts_clap_subcommands_and_rejects_garbage() {
    assert!(is_clap_kebab("verify-membrane"));
    assert!(is_clap_kebab("runtime-math-determinism-proofs"));
    assert!(is_clap_kebab("capture"));
    assert!(is_clap_kebab("env-fingerprint"));
    assert!(!is_clap_kebab(""));
    assert!(!is_clap_kebab("snake_case"));
    assert!(!is_clap_kebab("CamelCase"));
    assert!(!is_clap_kebab("-leading-dash"));
    assert!(!is_clap_kebab("trailing-dash-"));
    assert!(!is_clap_kebab("double--dash"));
}
