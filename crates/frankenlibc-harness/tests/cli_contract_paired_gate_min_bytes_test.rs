//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` is at least 2000 bytes
//! (bd-ffyl5). A real paired gate must declare a manifest-loading
//! helper, multiple `#[test]` functions, source-registration check,
//! and behavioral assertions — totalling well above 2KB. The
//! shortest current paired gate is ~7.2KB; the 2KB floor catches
//! stub gate files that would compile but assert nothing meaningful.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const MIN_PAIRED_GATE_BYTES: u64 = 2000;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn every_paired_gate_test_meets_min_byte_floor() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut smallest_seen = (u64::MAX, String::new());
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        // Self-referential meta-gates skip — they don't follow the paired template.
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let meta = std::fs::metadata(&path).map_err(|e| format!("metadata {path:?}: {e}"))?;
        let size = meta.len();
        if size < smallest_seen.0 {
            smallest_seen = (size, stem.to_string());
        }
        if size < MIN_PAIRED_GATE_BYTES {
            violations.push(format!(
                "{stem}: {size} bytes below floor {MIN_PAIRED_GATE_BYTES}"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate min-byte-floor violation(s) (floor={MIN_PAIRED_GATE_BYTES} bytes, smallest seen={} @ {} bytes):\n  {}",
            violations.len(),
            smallest_seen.1,
            smallest_seen.0,
            violations.join("\n  ")
        ));
    }
    Ok(())
}
