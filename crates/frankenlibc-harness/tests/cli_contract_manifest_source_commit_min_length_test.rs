//! Meta-gate: every `*_cli_contract.v1.json` manifest's
//! `source_commit` is at least 7 characters long (bd-3nm2n). 7 chars
//! is the canonical git short-hash floor (Linux kernel uses 12,
//! cargo uses 9, git's default is 7). Catches truncated commit ids
//! or stub strings shorter than the minimum-collision-free length.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_SOURCE_COMMIT_LEN: usize = 7;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_source_commit_meets_min_length() -> TestResult {
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
        let Some(s) = manifest.get("source_commit").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing source_commit"));
            checked += 1;
            continue;
        };
        let len = s.len();
        if len < shortest_seen.0 {
            shortest_seen = (len, s.to_string());
        }
        if len < MIN_SOURCE_COMMIT_LEN {
            violations.push(format!(
                "{name}: source_commit `{s}` length {len} below floor {MIN_SOURCE_COMMIT_LEN}"
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
            "{} source_commit min-length violation(s) (floor={MIN_SOURCE_COMMIT_LEN}, shortest=`{}` @ {} chars):\n  {}",
            violations.len(),
            shortest_seen.1,
            shortest_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
