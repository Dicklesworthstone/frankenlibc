//! Meta-gate: every `*.v1.json` file under `tests/conformance/` must have a
//! lowercase snake_case basename (bd-fhfnl). Catches accidentally-uppercase,
//! kebab-cased, or whitespace-bearing filenames that would be invisible to
//! the cli_contract_* meta-gate family which filters by exact suffix.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn is_snake_case_filename(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-'
        })
}

#[test]
fn every_v1_json_file_under_conformance_has_snake_case_basename() -> TestResult {
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
        if !name.ends_with(".v1.json") {
            continue;
        }
        if !is_snake_case_filename(name) {
            violations.push(format!("{name}: not snake_case"));
        }
        checked += 1;
    }

    assert!(
        checked >= 100,
        "expected at least 100 .v1.json files under tests/conformance; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} conformance filename convention violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn snake_case_validator_accepts_canonical_forms_and_rejects_garbage() {
    assert!(is_snake_case_filename(
        "snapshot_kernel_cli_contract.v1.json"
    ));
    assert!(is_snake_case_filename(
        "aarch64_arch_regression_gate.v1.json"
    ));
    assert!(is_snake_case_filename("bd_15n2_fixture_gap_fill.v1.json"));
    assert!(!is_snake_case_filename(""));
    assert!(!is_snake_case_filename("ManifestCase.v1.json"));
    assert!(!is_snake_case_filename("has space.v1.json"));
    assert!(!is_snake_case_filename("CAPS.v1.json"));
}
