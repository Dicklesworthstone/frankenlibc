//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares a `fn new(` helper
//! function (bd-ycfjf). Gate tests should be straight-line, not
//! factored into constructor helpers — the value of a gate is being
//! readable top-to-bottom without trampolining through factories.
//! One legacy gate (`shadow_run_cli_contract_test.rs`) is ratcheted
//! as exempt.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

const LEGACY_GATES_WITH_FN_NEW: &[&str] = &["shadow_run_cli_contract_test.rs"];

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn count_fn_new_decls(body: &str) -> usize {
    body.lines()
        .filter(|line| {
            let t = line.trim_start();
            t.starts_with("fn new(") || t.starts_with("pub fn new(")
        })
        .count()
}

#[test]
fn no_paired_gate_test_declares_fn_new() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_count = 0usize;
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
        let count = count_fn_new_decls(&body);
        if count > 0 {
            if LEGACY_GATES_WITH_FN_NEW.contains(&stem) {
                legacy_count += 1;
            } else {
                violations.push(format!("{stem}: declares {count} `fn new(` helper(s)"));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate `fn new(` violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }

    if legacy_count > LEGACY_GATES_WITH_FN_NEW.len() {
        return Err(format!(
            "legacy paired gates with `fn new(` rose to {legacy_count} (ceiling: {})",
            LEGACY_GATES_WITH_FN_NEW.len()
        ));
    }
    Ok(())
}

#[test]
fn fn_new_counter_handles_canonical_forms() {
    assert_eq!(count_fn_new_decls("fn new() -> Self {}"), 1);
    assert_eq!(count_fn_new_decls("pub fn new(x: u32) -> Self {}"), 1);
    assert_eq!(count_fn_new_decls("fn newt() {}"), 0);
    assert_eq!(count_fn_new_decls("// fn new()"), 0);
}
