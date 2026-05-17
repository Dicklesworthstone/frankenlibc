//! Meta-gate: every `*_cli_contract.v1.json` manifest's top-level
//! object has [10, 40] fields (bd-tc9mh). Catches truncated stubs
//! (under 10 fields) or schema-bloated manifests (over 40 fields)
//! that signal accidental concatenation or template explosion.
//! Corpus min/max is 15/25; the [10, 40] bounds give comfortable
//! headroom in both directions.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const MIN_FIELD_COUNT: usize = 10;
const MAX_FIELD_COUNT: usize = 40;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_field_count_within_bounds() -> TestResult {
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
        let Some(o) = manifest.as_object() else {
            violations.push(format!("{name}: top-level is not a JSON object"));
            checked += 1;
            continue;
        };
        let n = o.len();
        if n < min_seen.0 {
            min_seen = (n, name.to_string());
        }
        if n > max_seen.0 {
            max_seen = (n, name.to_string());
        }
        if !(MIN_FIELD_COUNT..=MAX_FIELD_COUNT).contains(&n) {
            violations.push(format!(
                "{name}: top-level has {n} fields (bounds [{MIN_FIELD_COUNT},{MAX_FIELD_COUNT}])"
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
            "{} field-count violation(s) (bounds=[{MIN_FIELD_COUNT},{MAX_FIELD_COUNT}], fewest={} @ {} fields, most={} @ {} fields):\n  {}",
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
