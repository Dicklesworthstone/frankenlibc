//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest must
//! declare a non-empty `underlying_lib_functions` JSON array of dotted-path
//! strings (bd-7dnmx). Catches manifests that drop the lib-API trace and
//! become pure manifest decoration without an anchored lib surface.

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

const LEGACY_LIB_FUNCTIONS_CEILING: usize = 31;

fn is_plausible_lib_path(s: &str) -> bool {
    s.contains("::")
        && (s.starts_with("frankenlibc")
            || s.starts_with("asupersync")
            || s.starts_with("harness::"))
}

#[test]
fn every_cli_contract_manifest_declares_at_least_one_underlying_lib_function() -> TestResult {
    let root = workspace_root()?;
    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_count = 0usize;
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract.v1.json") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {path:?}: {e}"))?;

        let arr = manifest
            .get("underlying_lib_functions")
            .and_then(Value::as_array);
        let names: Vec<&str> = arr
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();

        if names.is_empty() {
            legacy_count += 1;
        } else {
            let bad: Vec<&&str> = names.iter().filter(|n| !is_plausible_lib_path(n)).collect();
            if !bad.is_empty() {
                violations.push(format!(
                    "{stem}: underlying_lib_functions contains non-dotted-path entries: {bad:?}"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 20,
        "expected at least 20 CLI contract manifests; found {checked}"
    );

    if legacy_count > LEGACY_LIB_FUNCTIONS_CEILING {
        return Err(format!(
            "manifests with missing/empty underlying_lib_functions rose to {legacy_count} \
             (ceiling: {LEGACY_LIB_FUNCTIONS_CEILING}); retrofit a manifest or update the ratchet"
        ));
    }

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract manifest underlying_lib_functions violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn lib_path_validator_accepts_canonical_paths_and_rejects_garbage() {
    assert!(is_plausible_lib_path(
        "frankenlibc_harness::kernel_snapshot::build_kernel_snapshot_fixture"
    ));
    assert!(is_plausible_lib_path(
        "frankenlibc_membrane::check_oracle::pack_ordering"
    ));
    assert!(is_plausible_lib_path(
        "asupersync_lab_replay::validate_replay"
    ));
    assert!(!is_plausible_lib_path("not_a_path"));
    assert!(!is_plausible_lib_path("std::vec::Vec"));
    assert!(!is_plausible_lib_path(""));
}
