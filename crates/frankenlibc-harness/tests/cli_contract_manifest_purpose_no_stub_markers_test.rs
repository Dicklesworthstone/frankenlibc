//! Meta-gate: no `*_cli_contract.v1.json` manifest's `purpose`
//! string contains a stub marker — `TODO`, `TBD`, `FIXME`, or `XXX`
//! (bd-dc3ej). Catches placeholder descriptions that were never
//! filled in, or comments left behind from earlier scaffolding.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const STUB_MARKERS: &[&str] = &["TODO", "TBD", "FIXME", "XXX"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn find_stub_marker(text: &str) -> Option<&'static str> {
    STUB_MARKERS.iter().copied().find(|m| text.contains(m))
}

#[test]
fn no_cli_contract_manifest_purpose_contains_stub_marker() -> TestResult {
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
        let Some(s) = manifest.get("purpose").and_then(Value::as_str) else {
            continue;
        };
        if let Some(marker) = find_stub_marker(s) {
            violations.push(format!("{name}: purpose contains stub marker `{marker}`"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} purpose stub-marker violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn stub_marker_finder_handles_canonical_forms() {
    assert_eq!(find_stub_marker("this is fine"), None);
    assert_eq!(find_stub_marker("TODO: write"), Some("TODO"));
    assert_eq!(find_stub_marker("FIXME later"), Some("FIXME"));
    assert_eq!(find_stub_marker("TBD"), Some("TBD"));
    assert_eq!(find_stub_marker("XXX hack"), Some("XXX"));
}
