//! Meta-gate: every `*_cli_contract.v1.json` manifest is < 50KB
//! (bd-bj7ky). Catches manifest bloat from accidental inlining of
//! large fixtures, test corpora, or full transcripts that belong in
//! a separate evidence file rather than the contract manifest
//! itself. The full corpus currently sits well under this cap.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MAX_BYTES: u64 = 51_200;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_stays_under_max_size() -> TestResult {
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
        let metadata = std::fs::metadata(&path).map_err(|e| format!("metadata {path:?}: {e}"))?;
        let size = metadata.len();
        if size >= MAX_BYTES {
            violations.push(format!(
                "{name}: {size} bytes (must be < {MAX_BYTES} — manifest bloat suggests inline fixtures)"
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
            "{} manifest max-size violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
