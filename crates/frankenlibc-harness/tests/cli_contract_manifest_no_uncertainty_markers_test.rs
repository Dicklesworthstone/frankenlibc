//! Meta-gate: no `*_cli_contract.v1.json` manifest body contains
//! the case-insensitive substrings `untested` or `unverified`
//! (bd-cjrr0). Such language indicates the contract is not actually
//! load-bearing conformance evidence and should not be shipped into
//! the corpus where downstream HTML/markdown reports treat every
//! manifest as a positive assertion of subcommand behaviour.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MARKERS: &[&str] = &["untested", "unverified"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn find_markers(body: &str) -> Vec<&'static str> {
    let lower = body.to_ascii_lowercase();
    MARKERS
        .iter()
        .copied()
        .filter(|m| lower.contains(m))
        .collect()
}

#[test]
fn no_cli_contract_manifest_contains_uncertainty_markers() -> TestResult {
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
                "{name}: contains uncertainty marker(s): {}",
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
            "{} manifest uncertainty-marker violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn uncertainty_marker_detector_handles_canonical_forms() {
    assert_eq!(find_markers("foo untested bar"), vec!["untested"]);
    assert_eq!(find_markers("UNVERIFIED data"), vec!["unverified"]);
    assert_eq!(
        find_markers("Untested AND Unverified"),
        vec!["untested", "unverified"]
    );
    assert!(find_markers("nothing suspicious here").is_empty());
    assert!(find_markers("tested and verified").is_empty());
}
