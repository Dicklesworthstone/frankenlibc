//! Meta-gate: every `*_cli_contract.v1.json` manifest's `manifest_id`
//! ends with exactly one `-cli-contract` suffix (bd-i75nf). Catches
//! doubled suffixes like `foo-cli-contract-cli-contract` (template-
//! retrofit accident) or the suffix being missing entirely.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const CANONICAL_SUFFIX: &str = "-cli-contract";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn count_suffix_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

#[test]
fn every_cli_contract_manifest_id_has_exactly_one_canonical_suffix() -> TestResult {
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
        let Some(mid) = manifest.get("manifest_id").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing manifest_id"));
            checked += 1;
            continue;
        };
        let count = count_suffix_occurrences(mid, CANONICAL_SUFFIX);
        if count != 1 {
            violations.push(format!(
                "{name}: manifest_id `{mid}` contains {count} occurrence(s) of `{CANONICAL_SUFFIX}` (expected exactly 1)"
            ));
        } else if !mid.ends_with(CANONICAL_SUFFIX) {
            violations.push(format!(
                "{name}: manifest_id `{mid}` does not end with `{CANONICAL_SUFFIX}`"
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
            "{} manifest_id canonical-suffix violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn suffix_counter_handles_canonical_forms() {
    assert_eq!(
        count_suffix_occurrences("foo-cli-contract", "-cli-contract"),
        1
    );
    assert_eq!(
        count_suffix_occurrences("foo-cli-contract-cli-contract", "-cli-contract"),
        2
    );
    assert_eq!(count_suffix_occurrences("foo-bar", "-cli-contract"), 0);
    assert_eq!(
        count_suffix_occurrences("-cli-contract-cli-contract-x", "-cli-contract"),
        2
    );
}
