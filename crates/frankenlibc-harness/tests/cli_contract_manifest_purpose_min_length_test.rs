//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` declares a `purpose` field at least 20
//! characters long (bd-zhkf0). Catches stub purposes like `TODO`,
//! `foo`, or one-word descriptions that aren't useful for
//! documentation. The shortest current purpose is ~156 chars; the
//! 20-char floor absorbs natural variation while triggering on real
//! stub manifests.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_PURPOSE_LENGTH: usize = 20;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_purpose_meets_min_length() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut shortest_seen = (usize::MAX, String::new());
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
        match manifest.get("purpose").and_then(Value::as_str) {
            Some(s) => {
                if s.len() < shortest_seen.0 {
                    shortest_seen = (s.len(), name.to_string());
                }
                if s.len() < MIN_PURPOSE_LENGTH {
                    violations.push(format!(
                        "{name}: purpose `{s}` is {} chars (minimum {MIN_PURPOSE_LENGTH})",
                        s.len()
                    ));
                }
            }
            None => violations.push(format!("{name}: missing purpose field")),
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest purpose-length violation(s) (min={MIN_PURPOSE_LENGTH}, shortest seen={} @ {} chars):\n  {}",
            violations.len(),
            shortest_seen.1,
            shortest_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
