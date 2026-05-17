//! Meta-gate: when a `*_cli_contract.v1.json` manifest declares an
//! `io_pattern`, its string length is in [10, 150] characters
//! (bd-e20vz). Corpus min/max is 30/120; the [10, 150] bounds leave
//! ample headroom while catching truncated stubs and runaway
//! concatenation.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_IO_PATTERN_LEN: usize = 10;
const MAX_IO_PATTERN_LEN: usize = 150;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_io_pattern_length_within_bounds() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut min_seen = (usize::MAX, String::new());
    let mut max_seen = (0usize, String::new());
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
        let Some(s) = manifest.get("io_pattern").and_then(Value::as_str) else {
            continue;
        };
        let len = s.len();
        if len < min_seen.0 {
            min_seen = (len, s.to_string());
        }
        if len > max_seen.0 {
            max_seen = (len, s.to_string());
        }
        if !(MIN_IO_PATTERN_LEN..=MAX_IO_PATTERN_LEN).contains(&len) {
            violations.push(format!(
                "{name}: io_pattern `{s}` length {len} outside [{MIN_IO_PATTERN_LEN},{MAX_IO_PATTERN_LEN}]"
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
            "{} io_pattern length violation(s) (bounds=[{MIN_IO_PATTERN_LEN},{MAX_IO_PATTERN_LEN}], shortest=`{}` @ {} chars, longest=`{}` @ {} chars):\n  {}",
            violations.len(),
            min_seen.1,
            min_seen.0,
            max_seen.1,
            max_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
