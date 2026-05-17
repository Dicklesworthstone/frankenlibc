//! Meta-gate: every `*_cli_contract.v1.json` manifest file ends with
//! a trailing newline (bd-vnuvq). POSIX text-file convention; absence
//! produces "No newline at end of file" diff noise on every change.

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

fn ends_with_newline(body: &[u8]) -> bool {
    matches!(body.last(), Some(b'\n'))
}

#[test]
fn every_cli_contract_manifest_ends_with_trailing_newline() -> TestResult {
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
        let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !ends_with_newline(&bytes) {
            violations.push(format!("{name}: does not end with trailing newline"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} cli_contract manifest trailing-newline violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn trailing_newline_detector_handles_canonical_forms() {
    assert!(ends_with_newline(b"{}\n"));
    assert!(!ends_with_newline(b"{}"));
    assert!(!ends_with_newline(b""));
}
