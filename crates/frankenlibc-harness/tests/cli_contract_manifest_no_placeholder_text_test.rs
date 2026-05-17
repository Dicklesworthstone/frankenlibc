//! Meta-gate: no `*_cli_contract.v1.json` manifest body contains
//! the case-sensitive markers `TODO`, `FIXME`, `XXX`, or
//! `placeholder` (bd-1amv2). These markers indicate unfinished
//! manifest content. The contract manifest is load-bearing CI
//! evidence — incomplete manifests must not ship into the corpus
//! because they create stub-evidence indistinguishable from real
//! conformance proof during downstream report generation.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MARKERS: &[&str] = &["TODO", "FIXME", "XXX", "placeholder"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn find_markers(body: &str) -> Vec<&'static str> {
    MARKERS
        .iter()
        .copied()
        .filter(|m| body.contains(m))
        .collect()
}

#[test]
fn no_cli_contract_manifest_contains_placeholder_markers() -> TestResult {
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
        let found = find_markers(&body);
        if !found.is_empty() {
            violations.push(format!(
                "{name}: contains placeholder marker(s): {}",
                found.join(", ")
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
            "{} manifest placeholder-marker violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn placeholder_marker_detector_handles_canonical_forms() {
    assert_eq!(find_markers("foo TODO bar"), vec!["TODO"]);
    assert_eq!(find_markers("FIXME this"), vec!["FIXME"]);
    assert_eq!(find_markers("XXX skip"), vec!["XXX"]);
    assert_eq!(find_markers("a placeholder b"), vec!["placeholder"]);
    assert!(find_markers("nothing suspicious here").is_empty());
    assert!(find_markers("todo lowercase").is_empty());
}
