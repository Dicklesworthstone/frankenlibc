//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares an `extern crate` line
//! (bd-lgoua). Rust 2018+ resolves crate imports via `use` statements
//! without `extern crate`; the presence of `extern crate` indicates
//! stale code carried over from Rust 2015 or from a copy-paste from
//! an older codebase.

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

fn count_extern_crate_declarations(body: &str) -> usize {
    body.lines()
        .filter(|line| line.trim_start().starts_with("extern crate"))
        .count()
}

#[test]
fn no_paired_gate_test_declares_extern_crate() -> TestResult {
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
        let count = count_extern_crate_declarations(&body);
        if count > 0 {
            violations.push(format!(
                "{stem}: declares {count} `extern crate` line(s) (Rust 2018+ doesn't need them)"
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
            "{} paired gate test extern-crate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn extern_crate_counter_handles_canonical_forms() {
    assert_eq!(count_extern_crate_declarations("extern crate foo;"), 1);
    assert_eq!(
        count_extern_crate_declarations("  extern crate foo;\nfn x() {}"),
        1
    );
    assert_eq!(
        count_extern_crate_declarations("use std::path;\nfn x() {}"),
        0
    );
    assert_eq!(count_extern_crate_declarations("// extern crate foo;"), 0);
}
