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
    let forbidden = [
        ["Mut", "ex"].concat(),
        ["Rw", "Lock"].concat(),
        ["Ato", "mic"].concat(),
    ];
    let non_comment_body = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    forbidden
        .iter()
        .any(|needle| non_comment_body.contains(needle))
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
                "{stem}: references a sync primitive (gates should not need shared state)"
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
    assert!(contains_sync_primitive(&["Mut", "ex::new(0)"].concat()));
    assert!(contains_sync_primitive(&["Rw", "Lock::new(0)"].concat()));
    assert!(contains_sync_primitive(&["Ato", "micUsize"].concat()));
    assert!(!contains_sync_primitive("let x = 0;"));
    assert!(!contains_sync_primitive("Vec::new()"));
}
