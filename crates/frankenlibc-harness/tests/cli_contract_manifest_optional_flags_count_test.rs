//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` has at most 25 entries in its `optional_flags`
//! array (bd-0830k). Catches accidental optional-flag-list explosions
//! (sibling to the required_flags <= 20 sanity ceiling shipped in
//! bd-5wyz2). The highest current count is 11; the 25 ceiling absorbs
//! natural growth while triggering on real sprawl.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MAX_OPTIONAL_FLAGS: usize = 25;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_optional_flags_within_ceiling() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
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
        let Some(Value::Array(arr)) = manifest.get("optional_flags") else {
            continue;
        };
        let len = arr.len();
        if len > max_seen.0 {
            max_seen = (len, name.to_string());
        }
        if len > MAX_OPTIONAL_FLAGS {
            violations.push(format!(
                "{name}: optional_flags has {len} entries (ceiling {MAX_OPTIONAL_FLAGS})"
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
            "{} optional_flags count violation(s) (ceiling={MAX_OPTIONAL_FLAGS}, max seen={} @ {} entries):\n  {}",
            violations.len(),
            max_seen.1,
            max_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
