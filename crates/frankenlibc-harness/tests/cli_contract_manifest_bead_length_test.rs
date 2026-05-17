//! Meta-gate: every `*_cli_contract.v1.json` manifest's `bead`
//! field has length in [4, 12] characters (bd-zoslo). The `bd-`
//! prefix is 3 chars; the suffix is typically 5-7 chars, giving a
//! current corpus min/max of 7/10. [4,12] absorbs both shorter
//! single-segment-id experiments and the rare dotted variant
//! (`bd-2tq.4`) while triggering on truncated or absurdly long
//! placeholders.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_BEAD_LEN: usize = 4;
const MAX_BEAD_LEN: usize = 12;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_bead_length_within_bounds() -> TestResult {
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
        let Some(b) = manifest.get("bead").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing bead"));
            checked += 1;
            continue;
        };
        let len = b.len();
        if len < min_seen.0 {
            min_seen = (len, b.to_string());
        }
        if len > max_seen.0 {
            max_seen = (len, b.to_string());
        }
        if !(MIN_BEAD_LEN..=MAX_BEAD_LEN).contains(&len) {
            violations.push(format!(
                "{name}: bead `{b}` length {len} outside [{MIN_BEAD_LEN},{MAX_BEAD_LEN}]"
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
            "{} bead-length violation(s) (bounds=[{MIN_BEAD_LEN},{MAX_BEAD_LEN}], shortest=`{}` @ {} chars, longest=`{}` @ {} chars):\n  {}",
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
