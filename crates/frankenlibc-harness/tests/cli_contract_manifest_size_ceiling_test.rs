//! Meta-gate: every `*_cli_contract.v1.json` manifest under
//! `tests/conformance/` is at most 200KB in size (bd-eb5o5). CLI
//! contract manifests describe a single subcommand's surface; if one
//! grows past 200KB it is almost certainly carrying accidentally
//! checked-in fuzz dumps, debug traces, or a fixture explosion that
//! belongs in a separate file.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MAX_CLI_CONTRACT_MANIFEST_BYTES: u64 = 200 * 1024;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_within_size_ceiling() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut largest_seen_bytes = 0u64;
    let mut largest_seen_name = String::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let meta = std::fs::metadata(&path).map_err(|e| format!("metadata {path:?}: {e}"))?;
        let size = meta.len();
        if size > largest_seen_bytes {
            largest_seen_bytes = size;
            largest_seen_name = name.to_string();
        }
        if size > MAX_CLI_CONTRACT_MANIFEST_BYTES {
            violations.push(format!(
                "{name}: {size} bytes exceeds ceiling {MAX_CLI_CONTRACT_MANIFEST_BYTES}"
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
            "{} cli_contract manifest size-ceiling violation(s) (ceiling={MAX_CLI_CONTRACT_MANIFEST_BYTES} bytes, largest seen={largest_seen_name} @ {largest_seen_bytes} bytes):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
