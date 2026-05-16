//! Meta-gate: every `*_cli_contract.v1.json` manifest's `manifest_id`
//! has length in [10, 80] characters (bd-x85w2). Catches truncated
//! manifest_ids (e.g. only one segment) or absurdly long values. The
//! current corpus min/max is 19/51 chars; the 10/80 bounds give
//! comfortable headroom while triggering on real outliers.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_MANIFEST_ID_LEN: usize = 10;
const MAX_MANIFEST_ID_LEN: usize = 80;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_id_length_within_sanity_bounds() -> TestResult {
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
        let Some(mid) = manifest.get("manifest_id").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing manifest_id"));
            checked += 1;
            continue;
        };
        let len = mid.len();
        if len < min_seen.0 {
            min_seen = (len, mid.to_string());
        }
        if len > max_seen.0 {
            max_seen = (len, mid.to_string());
        }
        if len < MIN_MANIFEST_ID_LEN {
            violations.push(format!(
                "{name}: manifest_id `{mid}` length {len} below floor {MIN_MANIFEST_ID_LEN}"
            ));
        }
        if len > MAX_MANIFEST_ID_LEN {
            violations.push(format!(
                "{name}: manifest_id `{mid}` length {len} above ceiling {MAX_MANIFEST_ID_LEN}"
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
            "{} manifest_id length violation(s) (bounds=[{MIN_MANIFEST_ID_LEN},{MAX_MANIFEST_ID_LEN}], shortest=`{}` @ {} chars, longest=`{}` @ {} chars):\n  {}",
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
