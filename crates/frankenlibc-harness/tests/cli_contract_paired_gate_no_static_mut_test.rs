//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares a `static mut` (or
//! `mut static`) global (bd-qjulx). Mutable global state in gate
//! tests is a code smell — it makes test ordering matter and turns
//! independent assertions into hidden-dependency chains.

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

fn count_static_mut_decls(body: &str) -> usize {
    let mut n = 0usize;
    for line in body.lines() {
        let t = line.trim_start();
        if t.starts_with("static mut ") || t.starts_with("pub static mut ") {
            n += 1;
        }
    }
    n
}

#[test]
fn no_paired_gate_test_declares_static_mut() -> TestResult {
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
        let count = count_static_mut_decls(&body);
        if count > 0 {
            violations.push(format!("{stem}: {count} `static mut` declaration(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate `static mut` violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn static_mut_counter_handles_canonical_forms() {
    assert_eq!(count_static_mut_decls("static mut FOO: u32 = 0;"), 1);
    assert_eq!(count_static_mut_decls("pub static mut BAR: u32 = 0;"), 1);
    assert_eq!(count_static_mut_decls("  static mut BAZ: u32 = 0;"), 1);
    assert_eq!(count_static_mut_decls("static FOO: u32 = 0;"), 0);
    assert_eq!(count_static_mut_decls("// static mut FOO"), 0);
}
