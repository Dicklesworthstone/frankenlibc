//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares a `fn main` (or
//! `pub fn main`) (bd-peq5t). Integration test files under
//! `tests/` are compiled as test binaries — the test framework
//! generates main. A user-declared `fn main` would shadow that and
//! silently skip the tests.

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

fn count_fn_main_decls(body: &str) -> usize {
    body.lines()
        .filter(|line| {
            let t = line.trim_start();
            t.starts_with("fn main(") || t.starts_with("pub fn main(")
        })
        .count()
}

#[test]
fn no_paired_gate_test_declares_fn_main() -> TestResult {
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
        let count = count_fn_main_decls(&body);
        if count > 0 {
            violations.push(format!("{stem}: declares {count} `fn main` function(s)"));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate `fn main` violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn fn_main_counter_handles_canonical_forms() {
    assert_eq!(count_fn_main_decls("fn main() {}"), 1);
    assert_eq!(count_fn_main_decls("pub fn main() {}"), 1);
    assert_eq!(count_fn_main_decls("  fn main() -> () {}"), 1);
    assert_eq!(count_fn_main_decls("fn maintest() {}"), 0);
    assert_eq!(count_fn_main_decls("// fn main() {}"), 0);
}
