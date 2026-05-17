//! Meta-gate: every `*_cli_contract.v1.json` manifest is at least
//! 500 bytes (bd-y5t1a). Sanity floor — a real cli_contract manifest
//! must declare at least its schema_version + manifest_id + bead +
//! generated_utc + source_commit + subcommand_name + binary_target +
//! purpose + io_pattern (or output_contract) + required_flags +
//! optional_flags + summary + policy + rejected_evidence_kinds +
//! underlying_lib_functions. The shortest current manifest is 1410
//! bytes; the 500-byte floor catches truncated or near-empty stubs.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MIN_CLI_CONTRACT_MANIFEST_BYTES: u64 = 500;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_cli_contract_manifest_meets_min_size_floor() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut smallest_seen = (u64::MAX, String::new());
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
        if size < smallest_seen.0 {
            smallest_seen = (size, name.to_string());
        }
        if size < MIN_CLI_CONTRACT_MANIFEST_BYTES {
            violations.push(format!(
                "{name}: {size} bytes below floor {MIN_CLI_CONTRACT_MANIFEST_BYTES}"
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
            "{} cli_contract manifest min-size violation(s) (floor={MIN_CLI_CONTRACT_MANIFEST_BYTES} bytes, smallest seen={} @ {} bytes):\n  {}",
            violations.len(),
            smallest_seen.1,
            smallest_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
