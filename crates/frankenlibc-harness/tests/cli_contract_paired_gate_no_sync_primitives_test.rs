//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` references `Mutex`,
//! `RwLock`, or `Atomic` sync primitives (bd-x4s2z). Paired gates
//! spawn fresh subprocesses per assertion and run inside cargo
//! test's per-test isolation — they do not need shared mutable
//! state. Presence of sync primitives indicates either
//! over-engineering, or a shared-state hack that creates
//! cross-test ordering hazards.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn contains_sync_primitive(body: &str) -> bool {
    body.contains("Mutex") || body.contains("RwLock") || body.contains("Atomic")
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

#[test]
fn no_paired_gate_test_references_sync_primitive() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if contains_sync_primitive(&body) {
            violations.push(format!(
                "{stem}: references `Mutex`, `RwLock`, or `Atomic` (gates should not need sync primitives)"
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
            "{} paired gate sync-primitive violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn sync_primitive_detector_handles_canonical_forms() {
    assert!(contains_sync_primitive("Mutex::new(0)"));
    assert!(contains_sync_primitive("RwLock::new(0)"));
    assert!(contains_sync_primitive("AtomicUsize"));
    assert!(!contains_sync_primitive("let x = 0;"));
    assert!(!contains_sync_primitive("Vec::new()"));
}
